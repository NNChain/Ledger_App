//! Minimal bech32 (BIP-173) encoder, enough to render Cosmos account addresses.

use alloc::string::String;
use alloc::vec::Vec;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (*v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 0x1f);
    }
    out
}

fn to_base32(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in data {
        acc = (acc << 8) | (*b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    out
}

/// Encodes `data` (8-bit bytes) with the given human readable part.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let words = to_base32(data);
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&words);
    values.extend_from_slice(&[0u8; 6]);
    let pm = polymod(&values) ^ 1;

    let mut s = String::with_capacity(hrp.len() + 1 + words.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for w in &words {
        s.push(CHARSET[*w as usize] as char);
    }
    for i in 0..6 {
        let v = ((pm >> (5 * (5 - i))) & 0x1f) as usize;
        s.push(CHARSET[v] as char);
    }
    s
}
