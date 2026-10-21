//! Key derivation, address and signature helpers for the NNChain app.

use crate::bech32;
use crate::AppSW;
use alloc::string::String;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};
use ledger_device_sdk::hash::{ripemd::Ripemd160, sha2::Sha2_256, HashInit};

/// The only human readable part this app will produce.
pub const NNC_HRP: &str = "nnc";

const HARDENED: u32 = 0x8000_0000;
const PURPOSE: u32 = 44 | HARDENED;
const COIN_TYPE: u32 = 118 | HARDENED;

pub const PATH_BYTES: usize = 20;

pub type Path = [u32; 5];

/// Parses a Cosmos-style serialized path: five little-endian u32.
/// Allowed paths: m/44'/118'/account'/0/index.
pub fn parse_path(data: &[u8]) -> Result<Path, AppSW> {
    if data.len() != PATH_BYTES {
        return Err(AppSW::WrongLength);
    }
    let mut p: Path = [0; 5];
    for (i, chunk) in data.chunks(4).enumerate() {
        p[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    if p[0] != PURPOSE || p[1] != COIN_TYPE {
        return Err(AppSW::InvalidPath);
    }
    if p[2] & HARDENED == 0 || p[3] != 0 || p[4] & HARDENED != 0 {
        return Err(AppSW::InvalidPath);
    }
    Ok(p)
}

/// Returns the 33 byte compressed secp256k1 public key for `path`.
pub fn compressed_pubkey(path: &Path) -> Result<[u8; 33], AppSW> {
    let key = Secp256k1::derive_from_path(path);
    let pk = key.public_key().map_err(|_| AppSW::KeyDeriveFail)?;
    let uncompressed = pk.pubkey;
    let mut out = [0u8; 33];
    out[0] = if uncompressed[64] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(&uncompressed[1..33]);
    Ok(out)
}

/// Cosmos address bytes: RIPEMD160(SHA256(compressed pubkey)).
pub fn address_bytes(compressed: &[u8; 33]) -> Result<[u8; 20], AppSW> {
    let mut sha = Sha2_256::new();
    let mut digest = [0u8; 32];
    sha.hash(compressed, &mut digest)
        .map_err(|_| AppSW::HashFail)?;
    let mut rip = Ripemd160::new();
    let mut out = [0u8; 32];
    rip.hash(&digest, &mut out).map_err(|_| AppSW::HashFail)?;
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[..20]);
    Ok(addr)
}

pub fn address_string(hrp: &str, compressed: &[u8; 33]) -> Result<String, AppSW> {
    let bytes = address_bytes(compressed)?;
    Ok(bech32::encode(hrp, &bytes))
}

pub fn sha256(data: &[u8]) -> Result<[u8; 32], AppSW> {
    let mut sha = Sha2_256::new();
    let mut out = [0u8; 32];
    sha.hash(data, &mut out).map_err(|_| AppSW::HashFail)?;
    Ok(out)
}

/// Canonical low-S DER re-encoding (see `der.rs`).
pub fn der_low_s(sig: &[u8]) -> Result<([u8; 72], usize), AppSW> {
    crate::der::der_low_s(sig).map_err(|_| AppSW::TxSignFail)
}
