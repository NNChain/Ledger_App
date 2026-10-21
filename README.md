# NNChain Ledger app

Ledger device app for the **NNChain** network (a Cosmos SDK / CosmWasm chain, address prefix `nnc`).
Written in Rust for the Ledger **Stax** and **Flex** (NBGL touch interface).

The app is a signer: it derives secp256k1 keys at `m/44'/118'/account'/0/index`, shows **every field**
of an Amino JSON sign document on the device, and signs `SHA-256(document)` (ECDSA, RFC 6979, low-S
DER) only after the user approves. It speaks the same APDU protocol as the Ledger Cosmos app, so
existing Cosmos clients (cosmjs `LedgerSigner`, `ledger-cosmos-js`) work with it.

* Only the `nnc` address prefix is ever produced or displayed.
* Only documents with the Amino `StdSignDoc` structure are accepted; arbitrary JSON is refused.
* No blind signing exists.

## Documentation

| Document | Content |
|----------|---------|
| [`docs/APDU.md`](docs/APDU.md) | APDU specification, status words, limits |
| [`docs/AUDIT-READINESS.md`](docs/AUDIT-READINESS.md) | security properties, threat model, findings, test evidence |
| [`docs/LEDGER-CHECKLIST.md`](docs/LEDGER-CHECKLIST.md) | status against Ledger's audit checklist |
| [`docs/AI-SECURITY-REVIEW.md`](docs/AI-SECURITY-REVIEW.md) | AI-assisted review following Ledger's method |

## Build

With Ledger's builder image (Docker):

```
docker run --rm -v "$PWD":/app ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest \
  cargo ledger build flex      # or: stax
```

## Test

```
# Functional tests on the Speculos emulator (screenshots are compared)
pip install -r tests/standalone/requirements.txt
cd tests/standalone
pytest test_nnchain.py --device flex       # and --device stax
pytest test_audit_device.py --device flex

# Host-side unit, differential and fuzz tests (run from outside this directory,
# the app's .cargo/config.toml targets the device)
cargo test --release --manifest-path host-tests/Cargo.toml

# libFuzzer targets: see host-tests/fuzz/README.md
```

## Layout

```
src/                 app sources (Rust, no unsafe)
tests/standalone/    ragger functional tests and screenshots
host-tests/          host-side tests and libFuzzer targets
tools/               end-to-end check with the real cosmjs client
docs/                specification and audit documentation
```

## License

Apache-2.0, see [`LICENSE.md`](LICENSE.md). The project is based on Ledger's Rust app boilerplate.
