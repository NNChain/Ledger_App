# libFuzzer targets

Targets: `json_sign_doc`, `der_low_s`, `bech32_encode` (all hardware independent code from `../../src`).

The app's `.cargo/config.toml` targets the Ledger device, so fuzz from an export that does not carry it:

```
git archive --prefix=nnchain/ HEAD | tar -x -C /tmp && rm -rf /tmp/nnchain/.cargo
cd /tmp/nnchain/host-tests
cargo install cargo-fuzz            # once
cargo +nightly fuzz run json_sign_doc -- -max_total_time=300
cargo +nightly fuzz run der_low_s    -- -max_total_time=120
cargo +nightly fuzz run bech32_encode -- -max_total_time=60
```
