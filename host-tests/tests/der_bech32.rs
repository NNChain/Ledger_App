//! Differential tests for `src/der.rs` (low-S DER normalisation) and `src/bech32.rs`
//! against the `k256` and `bech32` reference crates.

extern crate alloc;

#[allow(dead_code)]
#[path = "../../src/der.rs"]
mod der;
#[allow(dead_code)]
#[path = "../../src/bech32.rs"]
mod bech32_dev;

use k256::ecdsa::Signature;
use k256::elliptic_curve::{ops::Reduce, PrimeField};
use k256::{Scalar, U256};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn rand_scalar(rng: &mut StdRng) -> Scalar {
    loop {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        // sometimes force small values to exercise leading-zero DER encodings
        let zeros = rng.gen_range(0..4);
        for x in b.iter_mut().take(if rng.gen_range(0..4) == 0 { zeros * 4 } else { 0 }) {
            *x = 0;
        }
        let s = <Scalar as Reduce<U256>>::reduce_bytes(&b.into());
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

#[test]
fn low_s_matches_k256_reference() {
    let mut rng = StdRng::seed_from_u64(42);
    let (mut high, mut low) = (0, 0);
    for _ in 0..300_000 {
        let r = rand_scalar(&mut rng);
        let s = rand_scalar(&mut rng);
        let sig = Signature::from_scalars(r.to_bytes(), s.to_bytes()).unwrap();
        let input = sig.to_der();
        let expect = sig.normalize_s().unwrap_or(sig).to_der();
        if sig.normalize_s().is_some() {
            high += 1;
        } else {
            low += 1;
        }
        let (out, n) = der::der_low_s(input.as_bytes()).expect("valid DER must be accepted");
        assert_eq!(&out[..n], expect.as_bytes(), "input {}", hex::encode(input.as_bytes()));
        // output must itself be valid, canonical and low-S
        let parsed = Signature::from_der(&out[..n]).unwrap();
        assert!(parsed.normalize_s().is_none(), "output must be low-S");
    }
    assert!(high > 100_000 && low > 100_000, "both branches exercised: {high}/{low}");
}

#[test]
fn der_rejects_malformed_and_never_panics() {
    let mut rng = StdRng::seed_from_u64(99);
    // pure noise
    for _ in 0..500_000 {
        let n = rng.gen_range(0..80);
        let bytes: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        if let Ok((out, n)) = der::der_low_s(&bytes) {
            let sig = Signature::from_der(&out[..n]).expect("accepted input must give valid DER");
            assert!(sig.normalize_s().is_none());
        }
    }
    // mutated valid signatures: accepted only if the reference parser also accepts the *input*
    for _ in 0..300_000 {
        let r = rand_scalar(&mut rng);
        let s = rand_scalar(&mut rng);
        let sig = Signature::from_scalars(r.to_bytes(), s.to_bytes()).unwrap();
        let mut b = sig.to_der().as_bytes().to_vec();
        for _ in 0..rng.gen_range(1..3) {
            match rng.gen_range(0..4) {
                0 => {
                    let i = rng.gen_range(0..b.len());
                    b[i] = rng.gen();
                }
                1 => {
                    b.pop();
                }
                2 => b.push(rng.gen()),
                _ => {
                    let i = rng.gen_range(0..b.len());
                    b.remove(i);
                }
            }
            if b.is_empty() {
                break;
            }
        }
        if let Ok((out, n)) = der::der_low_s(&b) {
            assert!(Signature::from_der(&b).is_ok(), "device accepted DER the reference rejects: {}", hex::encode(&b));
            assert!(Signature::from_der(&out[..n]).is_ok());
        }
    }
}

#[test]
fn bech32_matches_reference() {
    use ::bech32::{Bech32, Hrp};
    let mut rng = StdRng::seed_from_u64(5);
    for _ in 0..200_000 {
        let hrp_str = ["nnc", "cosmos", "nncvaloper", "a1b", "x"][rng.gen_range(0..4)];
        let n = if rng.gen() { 20 } else { rng.gen_range(0..40) };
        let data: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        let expect = ::bech32::encode::<Bech32>(Hrp::parse(hrp_str).unwrap(), &data).unwrap();
        assert_eq!(bech32_dev::encode(hrp_str, &data), expect);
    }
    // well-known Cosmos vector
    let addr = bech32_dev::encode("cosmos", &hex::decode("a5f46d9d3fa2b9d1d7e1e1c9e9e4b0d6b5f0c8aa").unwrap());
    assert!(addr.starts_with("cosmos1"));
}
