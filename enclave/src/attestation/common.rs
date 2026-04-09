use anyhow::{Result, anyhow, bail};
use foreign_types::ForeignTypeRef;
use openssl::sha::sha256;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509StoreContext};
use openssl_sys as ffi;
use std::slice;

pub fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    sha256(data).to_vec()
}

pub fn load_pem_certificates(roots_pem: &[&[u8]]) -> Result<Vec<X509>> {
    roots_pem
        .iter()
        .map(|root| X509::from_pem(root).map_err(Into::into))
        .collect()
}

pub fn verify_cert_chain(leaf: &X509, intermediates: &[X509], roots: &[X509]) -> Result<()> {
    let mut store_builder = X509StoreBuilder::new()?;
    for root in roots {
        store_builder.add_cert(root.clone())?;
    }

    let mut chain = Stack::new()?;
    for intermediate in intermediates {
        chain.push(intermediate.clone())?;
    }

    let store = store_builder.build();
    let mut ctx = X509StoreContext::new()?;
    ctx.init(&store, leaf, &chain, |c| c.verify_cert())?;
    Ok(())
}

pub fn certificate_extension_value(cert: &X509, target_oid: &str) -> Result<Option<Vec<u8>>> {
    let extension_count = unsafe { ffi::X509_get_ext_count(cert.as_ptr()) };
    let mut result = None;

    for index in 0..extension_count {
        let extension = unsafe { ffi::X509_get_ext(cert.as_ptr(), index) };
        if extension.is_null() {
            continue;
        }

        let oid = unsafe {
            let object = ffi::X509_EXTENSION_get_object(extension);
            oid_to_string(object)?
        };
        if oid != target_oid {
            continue;
        }

        let data = unsafe {
            let octet = ffi::X509_EXTENSION_get_data(extension);
            if octet.is_null() {
                bail!("certificate extension {target_oid} has no value")
            }
            asn1_string_bytes(octet.cast())
        };

        if result.replace(data).is_some() {
            bail!("certificate extension {target_oid} appears multiple times");
        }
    }

    Ok(result)
}

unsafe fn oid_to_string(object: *mut ffi::ASN1_OBJECT) -> Result<String> {
    if object.is_null() {
        bail!("ASN.1 object pointer is null");
    }

    let mut buffer = vec![0_u8; 128];
    let mut len =
        unsafe { ffi::OBJ_obj2txt(buffer.as_mut_ptr().cast(), buffer.len() as i32, object, 1) };
    if len < 0 {
        bail!("failed to stringify ASN.1 object");
    }
    if len as usize >= buffer.len() {
        buffer.resize(len as usize + 1, 0);
        len =
            unsafe { ffi::OBJ_obj2txt(buffer.as_mut_ptr().cast(), buffer.len() as i32, object, 1) };
        if len < 0 {
            bail!("failed to stringify ASN.1 object");
        }
    }

    Ok(String::from_utf8(buffer[..len as usize].to_vec())?)
}

unsafe fn asn1_string_bytes(value: *const ffi::ASN1_STRING) -> Vec<u8> {
    let len = unsafe { ffi::ASN1_STRING_length(value) as usize };
    let ptr = unsafe { ffi::ASN1_STRING_get0_data(value) };
    unsafe { slice::from_raw_parts(ptr, len) }.to_vec()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerTag {
    pub class: DerClass,
    pub constructed: bool,
    pub number: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct DerElement<'a> {
    pub tag: DerTag,
    pub value: &'a [u8],
}

pub fn parse_der(input: &[u8]) -> Result<(DerElement<'_>, &[u8])> {
    if input.is_empty() {
        bail!("missing DER tag");
    }

    let first = input[0];
    let class = match first >> 6 {
        0 => DerClass::Universal,
        1 => DerClass::Application,
        2 => DerClass::ContextSpecific,
        3 => DerClass::Private,
        _ => unreachable!(),
    };
    let constructed = (first & 0x20) != 0;
    let mut offset = 1;

    let mut tag_number = u32::from(first & 0x1f);
    if tag_number == 0x1f {
        tag_number = 0;
        loop {
            let byte = *input
                .get(offset)
                .ok_or_else(|| anyhow!("truncated DER high-tag-number"))?;
            offset += 1;
            tag_number = tag_number
                .checked_mul(128)
                .and_then(|value| value.checked_add(u32::from(byte & 0x7f)))
                .ok_or_else(|| anyhow!("DER tag number overflow"))?;
            if (byte & 0x80) == 0 {
                break;
            }
        }
    }

    let length_byte = *input
        .get(offset)
        .ok_or_else(|| anyhow!("missing DER length"))?;
    offset += 1;
    let value_len = if (length_byte & 0x80) == 0 {
        usize::from(length_byte)
    } else {
        let length_len = usize::from(length_byte & 0x7f);
        if length_len == 0 {
            bail!("indefinite DER length is unsupported");
        }
        if length_len > 8 {
            bail!("unsupported DER length width {length_len}");
        }
        let end = offset + length_len;
        let length_bytes = input
            .get(offset..end)
            .ok_or_else(|| anyhow!("truncated DER length payload"))?;
        offset = end;

        let mut value = 0_usize;
        for byte in length_bytes {
            value = value
                .checked_mul(256)
                .and_then(|len| len.checked_add(usize::from(*byte)))
                .ok_or_else(|| anyhow!("DER length overflow"))?;
        }
        value
    };

    let end = offset + value_len;
    let value = input
        .get(offset..end)
        .ok_or_else(|| anyhow!("truncated DER value"))?;
    let tag = DerTag {
        class,
        constructed,
        number: tag_number,
    };

    Ok((DerElement { tag, value }, &input[end..]))
}

pub fn parse_der_all(mut input: &[u8]) -> Result<Vec<DerElement<'_>>> {
    let mut elements = Vec::new();
    while !input.is_empty() {
        let (element, rest) = parse_der(input)?;
        elements.push(element);
        input = rest;
    }
    Ok(elements)
}

impl<'a> DerElement<'a> {
    pub fn expect_universal(self, number: u32) -> Result<Self> {
        if self.tag.class != DerClass::Universal || self.tag.number != number {
            bail!(
                "unexpected DER tag class {:?} number {}, expected universal {}",
                self.tag.class,
                self.tag.number,
                number
            );
        }
        Ok(self)
    }

    pub fn expect_context_specific(self, number: u32) -> Result<Self> {
        if self.tag.class != DerClass::ContextSpecific || self.tag.number != number {
            bail!(
                "unexpected DER tag class {:?} number {}, expected context-specific {}",
                self.tag.class,
                self.tag.number,
                number
            );
        }
        Ok(self)
    }

    pub fn children(self) -> Result<Vec<DerElement<'a>>> {
        if !self.tag.constructed {
            bail!("DER element is not constructed");
        }
        parse_der_all(self.value)
    }

    pub fn sequence(self) -> Result<Vec<DerElement<'a>>> {
        self.expect_universal(16)?.children()
    }

    pub fn set(self) -> Result<Vec<DerElement<'a>>> {
        self.expect_universal(17)?.children()
    }

    pub fn explicit(self) -> Result<DerElement<'a>> {
        let (inner, rest) = parse_der(self.value)?;
        if !rest.is_empty() {
            bail!("unexpected trailing data inside explicit DER tag");
        }
        Ok(inner)
    }

    pub fn octet_string(self) -> Result<&'a [u8]> {
        Ok(self.expect_universal(4)?.value)
    }

    pub fn integer_u64(self) -> Result<u64> {
        integer_to_u64(self.expect_universal(2)?.value)
    }

    pub fn enumerated_u64(self) -> Result<u64> {
        integer_to_u64(self.expect_universal(10)?.value)
    }

    pub fn boolean(self) -> Result<bool> {
        let value = self.expect_universal(1)?.value;
        if value.len() != 1 {
            bail!("invalid DER boolean");
        }
        Ok(value[0] != 0)
    }

    pub fn null(self) -> Result<()> {
        if self.expect_universal(5)?.value.is_empty() {
            Ok(())
        } else {
            bail!("invalid DER null");
        }
    }
}

pub fn find_context_specific<'a>(
    elements: &[DerElement<'a>],
    tag_number: u32,
) -> Option<DerElement<'a>> {
    elements.iter().copied().find(|element| {
        element.tag.class == DerClass::ContextSpecific && element.tag.number == tag_number
    })
}

fn integer_to_u64(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() {
        bail!("DER integer is empty");
    }
    if (bytes[0] & 0x80) != 0 {
        bail!("negative DER integers are unsupported");
    }

    let bytes = if bytes.len() > 1 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    };
    if bytes.len() > 8 {
        bail!("DER integer does not fit in u64");
    }

    let mut value = 0_u64;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|current| current.checked_add(u64::from(*byte)))
            .ok_or_else(|| anyhow!("DER integer overflow"))?;
    }
    Ok(value)
}
