# NNChain Ledger app: audit readiness package

Version 0.1.0 · Devices: Ledger **Stax** and **Flex** (NBGL) · Language: Rust (`no_std`) ·
SDK: `ledger_device_sdk` **=1.37.1**, API level 27 · Toolchain: `nightly-2025-12-05` (pinned in `rust-toolchain.toml`)

This document is the entry point for the independent security audit. It describes what the app is, what
it must guarantee, what was reviewed and tested internally, what was found and fixed, and what is
explicitly out of scope. Wire protocol: see [`APDU.md`](APDU.md).

## 1. What the app is

A **signer-only** app for the NNChain network (a Cosmos SDK 0.53 / CosmWasm chain, bech32 prefix `nnc`,
coin type 118). It does not parse transactions semantically. It:

1. derives secp256k1 keys at `m/44'/118'/account'/0/index` and returns the compressed public key and the
   `nnc1…` address;
2. receives an **Amino JSON sign doc** in chunks, shows **every field** to the user, and, only after the
   user approves, signs `SHA-256(doc)` with ECDSA (RFC 6979) and returns a low-S DER signature.

It speaks the same APDU protocol as the Ledger Cosmos app so existing Cosmos clients work unchanged.

Code size: about 1,100 lines of Rust in `src/` (no `unsafe`, no C), one direct dependency (`ledger_device_sdk`).

| File | Responsibility |
|------|----------------|
| `src/main.rs` | APDU dispatch, status words, home/status screens |
| `src/handlers/get_addr.rs` | public key / address (+ on-screen confirmation) |
| `src/handlers/sign.rs` | chunk reassembly, review, signing, session lifecycle |
| `src/json_view.rs` | strict JSON parser → ordered (label, value) list for display |
| `src/utils.rs` | path validation, key/address derivation, hashing |
| `src/der.rs` | low-S DER normalisation (hardware independent, fuzzed on host) |
| `src/bech32.rs` | bech32 encoder (hardware independent, fuzzed on host) |
| `src/app_ui/*` | NBGL screens |

## 1b. Ledger audit conditions: read this first

See [`LEDGER-CHECKLIST.md`](LEDGER-CHECKLIST.md). **Two conditions in Ledger's specification are not met yet**
and must be settled with Ledger before the external audit starts: (1) the app targets **Stax and Flex only**
(Ledger's conditions list Nano S Plus, Nano X, Stax and Flex), (2) Ledger must first validate the app
functionally (intro form and meeting). The CI workflows in `.github/` have not run yet (they need a GitHub
repository). The coin type `118` is shared with the Cosmos app; Ledger's app database may require its own.

## 2. Security properties the app must guarantee

| # | Property | Where enforced | Verified by |
|---|----------|----------------|-------------|
| P1 | **No signature without explicit user approval** of the exact displayed content | `sign.rs` (signing only after `ui_review_sign_doc` returns true) | `test_no_signature_without_user_approval`, `test_mutated_docs_fuzz` (never 0x9000 without approval) |
| P2 | **What you see is what is signed**: the signed bytes are the same buffer that was parsed and displayed; no re-serialisation | `sign.rs` (`ctx.buf` parsed, shown, hashed) | review, `test_reinit_discards_previous_chunks` |
| P3 | **Nothing is hidden**: control characters, bidi overrides, zero-width and look-alike (non-ASCII) characters cannot disguise text; every leaf of the document is shown | `json_view.rs` (non-ASCII → `\u{XXXX}`, controls/DEL rejected, `\n` etc. shown literally, `\\` shown doubled) | `spoofing_resistance`, differential fuzz |
| P4 | **Only the intended keys** can be used: purpose 44', coin 118', hardened account, change 0 | `utils.rs::parse_path`, manifest `path = ["44'/118'"]` | `rejects_other_coin_type`, `sign_rejects_wrong_path` |
| P5 | **No cross-session leakage**: chunks of one session never influence another; state wiped after every LAST | `sign.rs` (`reset`/`end_session`) | `test_session_state_is_wiped_after_signing`, `test_reinit_discards_previous_chunks` |
| P6 | **Signatures are valid for the chain**: low-S, DER, verifiable with the reported public key | `der.rs`, `sign.rs` | differential test vs `k256`, `test_sign_*`, cosmjs end-to-end |
| P7 | **Bounded resources**: malformed or hostile input cannot crash the app or exhaust the heap | limits below | `test_worst_case_docs_at_the_limits`, `test_signing_works_at_the_limits`, `test_large_docs_*`, `test_label_amplification_*`, `limits_are_enforced`, fuzzing |
| P9 | **Only real Amino sign docs are signed**: top level exactly `account_number, chain_id, fee, memo, msgs, sequence` (+ optional `timeout_height`), every message `{type, value}`; arbitrary JSON is refused | `json_view.rs::flatten_sign_doc` | `test_non_sign_doc_json_is_refused`, `sign_doc_shape_*` (host) |
| P10 | **Any other command ends a signing session**; chunks can never be completed across other commands | `main.rs`, `sign.rs::abort_session` | `test_other_commands_end_the_signing_session` |
| P8 | **Only `nnc` addresses** are ever produced/displayed, whatever HRP the client requests | `get_addr.rs` | `test_other_hrp_still_returns_nnc_address` |

Limits: sign doc ≤ 3072 bytes; JSON nesting ≤ 16; ≤ 80 displayed values; ≤ 3072 total displayed
bytes (labels + values); heap 28 KiB.

## 3. Trust model and attacker capabilities

* **Trusted**: the Ledger OS, the secure element, the SDK (`ledger_device_sdk`, `ledger_secure_sdk_sys`),
  the user's physical review of the screen.
* **Untrusted**: the host (wallet, extension, malware), every APDU byte, the content of the sign doc
  (a hostile dApp controls memo, contract messages, key names and string values).
* **Attacker goals considered**: obtain a signature without approval; make the user approve something
  different from what is signed; leak/derive keys outside the allowed path; crash or wedge the app;
  replay stale state across sessions.
* **Out of scope for the app**: whether a displayed transaction is *economically sensible* (the app is a
  generic clear-display signer, not a transaction semantics validator); host compromise that swaps the
  *intent* before the user looks at the screen (the screen is the control).

## 4. Internal review: findings and fixes

Review method: line-by-line manual review of all of `src/`, an LLM-assisted review following Ledger's
`SECURITY.REVIEW.md` method (`AI-SECURITY-REVIEW.md`), differential and libFuzzer fuzzing against reference
implementations, on-device (emulator) protocol fuzzing and stress, and an end-to-end run with the real
`@cosmjs/ledger-amino` client. All findings below are **fixed** and covered by regression tests. Severity
uses Ledger's scale ("before fix" = first internal build).

| ID | Before fix | Finding | Found by | Fix |
|----|-----------|---------|----------|-----|
| R1 | HIGH | **Arbitrary JSON could be signed** (no check that the document is an Amino sign doc): a signing oracle for attacker-chosen content | Ledger spec review | strict `StdSignDoc` structure required (`flatten_sign_doc`) |
| R2 | HIGH | **Display spoofing**: bidi overrides, zero-width and look-alike characters shown raw; a real backslash and a literal `\n` looked identical | review | all non-ASCII shown as `\u{XXXX}`; raw control characters and DEL rejected; backslash shown doubled; lone surrogates shown literally |
| R3 | WARNING | **Heap exhaustion (availability)**: a ~3.5 KB / 65-field doc crashed the app (16 KiB heap) and a ~4 KB / 80-field doc still crashed it at 24 KiB; a tiny deeply nested doc could expand into huge label text | emulator stress (found twice) | per-item memory slimmed; doc ≤ 3072 B, ≤ 80 values, ≤ 3072 display bytes, heap 28 KiB; worst-case shapes tested reviewed and signed |
| R4 | WARNING | **Stale session state**: buffer and path stayed after LAST, and a session could continue across other commands | review | state wiped after every LAST; any other command ends the session |
| R5 | WARNING | **Integer overflow** in the message-index label (`n + 1` for a key like `18446744073709551615`) | Rust arithmetic review | `saturating_add`; regression test |
| R6 | WARNING | **Input strictness**: lax JSON numbers (`1-+2.`), DER reader accepting negative / non-minimal integers and trailing bytes, coin merging joining non-coin leaves | differential fuzzing | strict RFC 8259 numbers, strict DER, merge only string/number leaves |
| R7 | INFO | cosmjs asks the public key with HRP `cosmos`; unused import and one clippy lint; SDK dependency not pinned | cosmjs e2e, clippy | `nnc` always produced; warnings fixed; SDK pinned `=1.37.1` |

During the fix for R1 the new fuzz test found that an empty object (`{}`) bypassed the structure check
through the parser's empty-object shortcut. It was fixed before any release
(`sign_doc_shape_rejects_everything_else`).

Note (not a defect): after a user rejects/approves, the NBGL status screen is shown and the device
answers `0x6901` (busy) to APDUs sent before it disappears. This is standard Ledger behaviour; clients
retry. On real devices the status screen self-dismisses; the emulator needs a tap (handled in tests).

## 5. Test and fuzz evidence

Reproduction commands are in section 7.

**Host-side (x86), `host-tests/`: pure logic, differential against reference crates**

| Target | Reference | Volume | Result |
|--------|-----------|--------|--------|
| `json_view` valid documents | `serde_json` (values, order, limits) | 60,000 random docs | identical |
| `flatten_sign_doc` structure | hand-written accept/reject table + mutation fuzz | 18 cases + 200,000 mutations | refuses everything that is not a sign doc |
| `json_view` mutated documents | `serde_json` acceptance | 250,000 | never panics; accepts ⊆ valid JSON (documented exceptions: surrogate escapes, f64-range numbers) |
| `json_view` random bytes / JSON-punctuation noise | n/a | 800,000 | never panics |
| `der_low_s` | `k256` (`normalize_s`, `from_der`) | 300,000 valid + 800,000 malformed/mutated | identical output; malformed rejected |
| `bech32::encode` | `bech32` 0.11 | 200,000 | identical |
| Limits & spoofing | n/a | targeted | depth 16, 80 items, 3072 bytes; label amplification; bidi/zero-width/homoglyph/escape cases |

**libFuzzer (coverage-guided, `host-tests/fuzz/`)**

| Target | Runs | Result |
|--------|------|--------|
| `json_sign_doc` (parser, with output invariants) | 12,493,912 (4 min) | no crash, no invariant violation |
| `der_low_s` (idempotent, valid DER out) | 51,447,002 (90 s) | none |
| `bech32_encode` | 3,177,240 (60 s) | none |

**Static analysis:** `cargo clippy --release --target flex|stax -- -D warnings` clean on both devices;
`cargo audit`: 64 crate dependencies scanned against 1,338 RustSec advisories, **0 vulnerabilities**.

**On-device (Speculos, API level 27, real Ledger firmware logic), `tests/standalone/`**

* `test_nnchain.py`: 17 functional tests, **with screenshot (snapshot) comparison** of the address confirm/reject, send, reject, long memo, escapes, tokenfactory mint and nested wasm flows on both devices (`tests/standalone/snapshots/`); (version, address, derivation vs independent BIP32 reference,
  path/HRP rules, sign send / multi-chunk / escapes / tokenfactory / nested wasm, reject, invalid JSON,
  oversize, signature verification with low-S).
* `test_audit_device.py`: 29 tests (Flex and Stax): 3,000 random APDUs, wrong CLA, 250 mutated sign docs,
  no-signature-without-approval, session wipe, re-INIT isolation, key/account binding, HRP check, heap
  stress (large docs, label amplification, three worst-case shapes reviewed and two signed, 40 repeated
  sessions), oversize and over-field-limit handling, non-sign-doc JSON refusal, session ended by other commands.
* `tools/e2e-cosmjs.js`: the real `@cosmjs/ledger-amino` `LedgerSigner` signs a bank send on the emulated
  Flex; the signature verifies against the device key and the signed document is identical to the
  requested one.

Both Flex and Stax builds are exercised. A test on **physical** Stax and Flex devices is scheduled as the
last step before submission and is not part of this evidence.

## 6. Known limitations and design decisions (for the auditor's attention)

1. **Generic display, no semantic validation.** Message types are shown as their raw type string; amounts
   are shown in base units ("1000000 nnc"). There is no denomination formatting and no message allow-list
   (all NNChain message types must be signable).
2. **Only SIGN_MODE_LEGACY_AMINO_JSON.** Textual and direct modes are refused (`0x6B00`). The chain's
   tokenfactory messages `MsgMintAndSendTokens`, `MsgCreateDenom`, `MsgUpdateDenom`, `MsgUpdateOwner`
   currently lack an `amino.name` on the chain side; a chain upgrade is planned separately and is not part
   of the app.
3. **Labels come from the document.** JSON key names are shown as labels (escaped like values). A hostile
   document can choose keys that look like benign labels; the *values and every leaf are still shown*.
4. **Coin type 118** is shared with the Cosmos app; keys derived are identical to those of the Cosmos app
   for the same seed (chain decision).
5. **Large documents** (> 3072 bytes or > 80 displayed values, e.g. contract uploads, very large batches) cannot be signed on the device by design. The limits are set by device RAM: Ledger's `NbglStreamingReview` could raise them and is a possible later improvement.
6. The app does not display the *address of the signer* during signing (the chain binds the signature to
   the account); it displays the doc as provided.
7. Status screens block APDU handling briefly (`0x6901`), as in all NBGL apps.

## 7. How to reproduce

```
# Build (Ledger builder image) — flex or stax
docker run --rm -v "$PWD":/app ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest cargo ledger build flex

# Static analysis (inside the builder image): cargo clippy --release --target flex -- -D warnings ; cargo audit
# Host-side fuzz / differential tests (run from OUTSIDE the app dir, see host-tests/Cargo.toml)
cd .. && cargo test --release --manifest-path <app>/host-tests/Cargo.toml
# libFuzzer: see host-tests/fuzz/README.md

# On-device tests on the Speculos emulator (pip: speculos, ragger[speculos], ecdsa, bip-utils, pycryptodome)
cd tests/standalone
pytest test_nnchain.py       --device flex      # and --device stax (compares screenshots)
pytest test_audit_device.py  --device flex      # ~7 min

# End-to-end with the real cosmjs client (needs speculos --apdu-port 9999 --api-port 5000 and node)
node tools/e2e-cosmjs.js
```

## 8. Suggested audit focus

1. `sign.rs`: P1, P2, P5 (state machine, buffer lifetime, UI call).
2. `json_view.rs`: P3, P7 (parser strictness, escaping, limits, recursion).
3. `utils.rs` / `get_addr.rs`: P4, P8 (path rules, key derivation, HRP handling).
4. `der.rs`: P6.
5. SDK integration: `Comm` use, panic handler (`exiting_panic`), manifest permissions
   (`curve = secp256k1`, `path = 44'/118'`, `flags = 0`), memory layout (`HEAP_SIZE`).
