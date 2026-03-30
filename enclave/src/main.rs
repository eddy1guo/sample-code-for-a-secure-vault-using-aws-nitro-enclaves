// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use anyhow::{Error, Result, anyhow};
use enclave_vault::attestation::get_attestation_document;
use enclave_vault::models::{
    CreateWalletKeyRequest, EnclaveAction, ParentRequest, WalletSignRequest,
};
use enclave_vault::{
    constants::{ENCLAVE_PORT, MAX_CONCURRENT_CONNECTIONS},
    expressions::execute_expressions,
    models::{EnclaveRequest, EnclaveResponse},
    protocol::{recv_message, send_message},
};
use serde_json::Value;
use vsock::VsockListener;

// Avoid musl's default allocator due to terrible performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[inline]
fn parse_payload(payload_buffer: &[u8]) -> Result<EnclaveAction> {
    let payload: EnclaveAction = serde_json::from_slice(payload_buffer)
        .map_err(|err| anyhow!("failed to deserialize payload: {err:?}"))?;
    Ok(payload)
}

#[inline]
fn send_error<W: Write>(mut stream: W, err: Error) -> Result<()> {
    // Sanitize error message to avoid leaking sensitive data
    let sanitized_msg = sanitize_error_message(&err);
    println!("[enclave error] {sanitized_msg}");

    let response = EnclaveResponse::error(err);

    let payload: String = serde_json::to_string(&response)
        .map_err(|err| anyhow!("failed to serialize error response: {err:?}"))?;

    if let Err(err) = send_message(&mut stream, &payload) {
        let sanitized = sanitize_error_message(&err);
        println!("[enclave error] failed to send error: {sanitized}");
    }

    Ok(())
}

/// Sanitizes error messages to prevent sensitive data leakage in logs.
/// Removes potential field values, keys, or other sensitive content.
#[inline]
fn sanitize_error_message(err: &Error) -> String {
    let msg = err.to_string();
    // Truncate very long error messages that might contain data
    if msg.len() > 200 {
        format!("{}... (truncated)", &msg[..200])
    } else {
        msg
    }
}

//
fn handle_decrypt(request: EnclaveRequest<ParentRequest>) -> Result<(Value, Vec<Error>)> {
    use serde_json::{Map, Value};
    // Decrypt the individual field values (uses rayon for parallelization internally)
    let (decrypted_fields, errors) = request.decrypt_fields()?;
    let value = Value::Object(decrypted_fields.into_iter().collect::<Map<String, Value>>());
    Ok((value, errors))
}

fn handle_wallet_sign(request: EnclaveRequest<WalletSignRequest>) -> Result<(Value, Vec<Error>)> {
    todo!()
}

fn handle_create_wallet_key(
    request: EnclaveRequest<CreateWalletKeyRequest>,
) -> Result<(Value, Vec<Error>)> {
    use serde_json::{Map, Value};
    println!("start to create wallet key");
    // Decrypt the individual field values (uses rayon for parallelization internally)
    let (prikey, pubkey) = request.create()?;
    let mut fields: HashMap<String, Value> = Default::default();
    fields.insert("prikey".to_string(), prikey.into());
    fields.insert("pubkey".to_string(), pubkey.into());
    let value = Value::Object(fields.into_iter().collect::<Map<String, Value>>());
    Ok((value, Vec::new()))
}

fn handle_client<S: Read + Write>(mut stream: S) -> Result<()> {
    println!("[enclave] handling client");

    let (client_nonce, (response, errors)) = match recv_message(&mut stream)
        .map_err(|err| anyhow!("failed to receive message: {err:?}"))
    {
        Ok(payload_buffer) => match parse_payload(&payload_buffer) {
            Ok(EnclaveAction::Decrypt { inner }) => {
                ("0".to_string().into_bytes(), handle_decrypt(inner)?)
            }
            Ok(EnclaveAction::WalletSign { inner }) => (
                inner.request.nonce.clone().into_bytes(),
                handle_wallet_sign(inner)?,
            ),
            Ok(EnclaveAction::CreateWalletKey { inner }) => (
                inner.request.nonce.clone().into_bytes(),
                handle_create_wallet_key(inner)?,
            ),
            Err(err) => return send_error(stream, err),
        },
        Err(err) => return send_error(stream, err),
    };

    let payload: String = serde_json::to_string(&response)
        .map_err(|err| anyhow!("failed to serialize response: {err:?}"))?;

    println!("[enclave] sending response to parent: payload {}", payload);

    let attestation_document = get_attestation_document(payload.as_bytes(), &client_nonce).unwrap();
    let final_fields = [(
        "attestation".to_string(),
        hex::encode(&attestation_document).into(),
    )]
    .into();

    let response = EnclaveResponse::new(final_fields, Some(errors));
    println!(
        "[enclave] sending response to parent: EnclaveResponse {:?}",
        response
    );

    let payload: String = serde_json::to_string(&response)
        .map_err(|err| anyhow!("failed to serialize response: {err:?}"))?;

    if let Err(err) = send_message(&mut stream, &payload)
        .map_err(|err| anyhow!("Failed to send message: {err:?}"))
    {
        return send_error(stream, err);
    }

    println!("[enclave] finished client");

    Ok(())
}

fn main() -> Result<()> {
    eprintln!("[enclave] init 777");
    let listener = match VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, ENCLAVE_PORT) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "[enclave fatal] failed to bind listener on port {}: {:?}",
                ENCLAVE_PORT, e
            );
            std::process::exit(1);
        }
    };

    eprintln!("[enclave] listening on port {ENCLAVE_PORT}");
    eprintln!(
        "[enclave] max concurrent connections: {}",
        MAX_CONCURRENT_CONNECTIONS
    );

    // Track active connections to prevent resource exhaustion DoS
    let active_connections = Arc::new(AtomicUsize::new(0));

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // Check if we've reached the connection limit
                let current = active_connections.load(Ordering::SeqCst);
                if current >= MAX_CONCURRENT_CONNECTIONS {
                    println!(
                        "[enclave warning] connection limit reached ({}/{}), rejecting",
                        current, MAX_CONCURRENT_CONNECTIONS
                    );
                    // Drop the stream to close the connection
                    drop(stream);
                    continue;
                }

                // Increment connection count
                active_connections.fetch_add(1, Ordering::SeqCst);
                let connections = Arc::clone(&active_connections);

                // Spawn a new thread to handle each client concurrently
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream) {
                        let sanitized = sanitize_error_message(&err);
                        println!("[enclave error] {sanitized}");
                    }
                    // Decrement connection count when done
                    connections.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) => {
                println!("[enclave error] failed to accept connection: {:?}", e);
                continue;
            }
        }
    }

    Ok(())
}
