//! Pure (hardware independent) DER signature helpers.
//!
//! Kept free of any Ledger SDK dependency so it can be fuzzed and tested on a host.

#[derive(Debug, PartialEq, Eq)]
pub struct DerError;

// secp256k1 group order n and n/2, big-endian.
const N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];
const HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Reads one DER INTEGER at `pos`, returns the value left padded to 32 bytes
/// and the position after it.
fn der_int(sig: &[u8], pos: usize) -> Result<([u8; 32], usize), DerError> {
    if pos + 2 > sig.len() || sig[pos] != 0x02 {
        return Err(DerError);
    }
    let len = sig[pos + 1] as usize;
    let start = pos + 2;
    let end = start + len;
    if end > sig.len() || len == 0 {
        return Err(DerError);
    }
    let mut v = &sig[start..end];
    // DER integers are minimal two's complement: no negative values and no
    // redundant leading zero byte.
    if v[0] & 0x80 != 0 || (v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0) {
        return Err(DerError);
    }
    if v[0] == 0 {
        v = &v[1..];
    }
    if v.len() > 32 || v.is_empty() {
        return Err(DerError);
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Ok((out, end))
}

fn gt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    false
}

fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = a[i] as i16 - b[i] as i16 - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u8;
    }
    out
}

fn put_der_int(out: &mut [u8], pos: &mut usize, v: &[u8; 32]) {
    let mut start = 0;
    while start < 31 && v[start] == 0 {
        start += 1;
    }
    let body = &v[start..];
    let pad = body[0] & 0x80 != 0;
    out[*pos] = 0x02;
    out[*pos + 1] = (body.len() + pad as usize) as u8;
    *pos += 2;
    if pad {
        out[*pos] = 0;
        *pos += 1;
    }
    out[*pos..*pos + body.len()].copy_from_slice(body);
    *pos += body.len();
}

/// Re-encodes a DER signature with a canonical low-S value, as required by
/// the Cosmos SDK. Returns the buffer and the used length.
pub fn der_low_s(sig: &[u8]) -> Result<([u8; 72], usize), DerError> {
    // SEQUENCE { INTEGER r, INTEGER s }, short-form length, no trailing bytes.
    if sig.len() < 8 || sig[0] != 0x30 || sig[1] as usize != sig.len() - 2 {
        return Err(DerError);
    }
    let (r, next) = der_int(sig, 2)?;
    let (mut s, end) = der_int(sig, next)?;
    if end != sig.len() {
        return Err(DerError);
    }
    if r == [0u8; 32] || s == [0u8; 32] {
        return Err(DerError);
    }
    if gt(&s, &HALF_N) {
        s = sub(&N, &s);
    }
    let mut out = [0u8; 72];
    let mut pos = 2;
    put_der_int(&mut out, &mut pos, &r);
    put_der_int(&mut out, &mut pos, &s);
    out[0] = 0x30;
    out[1] = (pos - 2) as u8;
    Ok((out, pos))
}
