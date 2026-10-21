#![no_main]
//! libFuzzer target: bech32 encoder (`src/bech32.rs`).
extern crate alloc;

#[allow(dead_code)]
#[path = "../../../src/bech32.rs"]
mod bech32;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = bech32::encode("nnc", data);
    assert!(s.starts_with("nnc1"));
    assert!(s.is_ascii());
    assert_eq!(s.len(), 4 + (data.len() * 8).div_ceil(5) + 6);
});
