#![no_main]
//! libFuzzer target: DER low-S normalisation (`src/der.rs`).
#[allow(dead_code)]
#[path = "../../../src/der.rs"]
mod der;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((out, n)) = der::der_low_s(data) {
        assert!((8..=72).contains(&n));
        assert_eq!(out[0], 0x30);
        assert_eq!(out[1] as usize, n - 2);
        // idempotent: normalising an already normalised signature changes nothing
        let (again, m) = der::der_low_s(&out[..n]).expect("output must be valid DER");
        assert_eq!(&again[..m], &out[..n]);
    }
});
