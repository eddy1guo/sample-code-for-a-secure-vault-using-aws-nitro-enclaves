// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use anyhow::{Error, Result, anyhow, bail};
use enclave_vault::credential::aws::get_attestation_document;
use enclave_vault::error::ErrorType;
use enclave_vault::model::{ModifyPasswordRequest, RecoverWalletRequest, SignRequest};
use enclave_vault::models::{CreateWalletKeyRequest, EnclaveAction, TeeClientRegisterRequest};
use enclave_vault::{
    constants::{ENCLAVE_PORT, MAX_CONCURRENT_CONNECTIONS},
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

#[inline]
fn handle_request<T, F>(label: &str, f: F) -> Result<Value>
where
    T: serde::Serialize,
    F: FnOnce() -> Result<T>,
{
    println!("{label}");
    let data = f()?;
    Ok(serde_json::json!({
        "data": serde_json::to_value(data)?
    }))
}

#[inline]
fn dispatch_action(action: EnclaveAction) -> Result<Value> {
    match action {
        EnclaveAction::Sign { inner } => handle_request("start handle_sign", || inner.execute()),
        EnclaveAction::SignWithoutAssertion { inner } => {
            handle_request("start handle_sign_without_assertion", || inner.execute())
        }
        EnclaveAction::CreateWalletKey { inner } => {
            handle_request("start handle_create_wallet_key", || inner.execute())
        }
        EnclaveAction::ModifyPassword { inner } => {
            handle_request("start handle_modify_password", || inner.execute())
        }
        EnclaveAction::RecoverWallet { inner } => {
            handle_request("start handle_recover_wallet", || inner.execute())
        }
        EnclaveAction::TeeClientRegister { inner } => {
            handle_request("start handle_tee_client_register", || inner.execute())
        }
    }
}

#[inline]
fn read_request<S: Read>(stream: &mut S) -> Result<EnclaveAction> {
    let payload_buffer =
        recv_message(stream).map_err(|err| anyhow!("failed to receive message: {err:?}"))?;
    parse_payload(&payload_buffer)
}

fn handle_client<S: Read + Write>(mut stream: S) -> Result<()> {
    println!("[enclave] handling client");

    let response = match read_request(&mut stream) {
        Ok(action) => dispatch_action(action),
        Err(err) => return send_error(stream, err),
    };

    let (final_fields, errors): (HashMap<String, Value>, Option<Vec<Error>>) = match response {
        Ok(response) => {
            let payload: String = serde_json::to_string(&response)
                .map_err(|err| anyhow!("failed to serialize response: {err:?}"))?;

            println!("[enclave] sending response to parent: payload {}", payload);

            let attestation_document = get_attestation_document(payload.as_bytes()).unwrap();
            let final_fields = [(
                "attestation".to_string(),
                hex::encode(&attestation_document).into(),
            )]
            .into();

            (final_fields, None)
        }
        Err(err) => {
            if err.is_biz_error() {
                (Default::default(), Some(vec![err]))
            } else {
                return Err(err);
            }
        }
    };

    let response = EnclaveResponse::new(final_fields, errors);
    println!(
        "[enclave] sending response to parent: EnclaveResponse {:?}",
        response
    );

    //如何防止嵌套
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
