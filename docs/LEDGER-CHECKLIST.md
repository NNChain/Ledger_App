# Ledger security-audit checklist: self-assessment

Reference: Ledger "Security audit" specification (conditions, specification, deliverables checklist).
Status as of version 0.1.0 (commit tagged `v0.1.0-audit`). **This is the developer's own assessment,
not an audit.** "Open" items must be resolved or agreed with Ledger before the external audit starts.

## Conditions to start an external audit

| Condition | Status | Notes |
|-----------|--------|-------|
| Device app works with **all** Ledger signers (Nano S Plus, Nano X, Stax, Flex) | **OPEN** | Built and tested for **Stax and Flex only** (client decision). Ledger's conditions list all four. Needs a decision: add Nano S+/X (UI, heap and test work) or obtain Ledger's agreement to a Stax/Flex-only app. |
| Ledger team has **functionally validated** the app | **OPEN** | Requires Ledger's intro form and meeting first (Ledger account / partner path). |
| App remains functional after the audit | n/a | |

## Specification

| Area | Requirement | Status | Evidence / gap |
|------|-------------|--------|----------------|
| AI-assisted review | An LLM review using Ledger's `SECURITY.REVIEW.md` method | Done (developer side) | `docs/AI-SECURITY-REVIEW.md`. The external auditor must repeat it independently. |
| Privileges | Least-privilege flags, curves, BIP32 prefix | Done | `flags = 0`, `curve = secp256k1`, `path = 44'/118'`. **Open**: Ledger's app database must declare the path; `118` is the Cosmos app's coin type, Ledger may require its own. |
| Clear signing | Every signing action approved; all important info visible | Done | Whole sign doc displayed; no blind signing exists. Generic display (raw type string, base units). Dangerous message types (authz grants, ownership changes, IBC transfers…) are shown like any other message: auditor to assess. |
| Clear signing | Review with Speculos + functional-test **snapshots** for every flow | Done | `tests/standalone/snapshots/<device>/…` for address confirm/reject, send, reject, long memo, escapes, tokenfactory mint, nested wasm. |
| Compilation | Boilerplate / SDK build tooling, no warnings, no deprecated calls | Done | Built with Ledger's `cargo ledger` builder image from the Rust boilerplate; 0 compiler warnings, clippy clean. |
| CI | Guidelines enforcer and build workflows; all pipelines pass | **Partly** | Workflows run on GitHub (repository `NNChain/Ledger_App`). Build (Flex, Stax), host tests, clippy, rustfmt and `cargo-audit` pass. The guidelines enforcer still fails one check that only Ledger can resolve: *Check APP_LOAD_PARAMS* needs the app (`app-nnchain`) registered in Ledger's app database, with its derivation path. |
| Tests | Unit, functional, fuzzing; all pass on all devices | Partly | Unit/differential: 10 host tests (pass). Functional: Stax and Flex (pass). Fuzzing: libFuzzer targets in `host-tests/fuzz/` (about 67 million runs, no findings). Nano devices: not applicable until supported. |
| Static analysis (Rust) | `clippy` clean; `cargo-audit` on dependencies | Done | clippy `-D warnings` clean on Stax and Flex; `cargo audit`: 0 vulnerabilities in 64 dependencies (`AUDIT-READINESS.md` §5). |
| Vulnerabilities | No medium/high; input validation; state machine; Rust specifics | Done | 7 findings (2 HIGH, 4 WARNING, 1 INFO by Ledger's scale) fixed (`AUDIT-READINESS.md` §4, `AI-SECURITY-REVIEW.md`); no `unsafe`; arithmetic reviewed; no panics on malformed input in fuzzing. |
| Cryptography | Secrets erased, no re-implemented primitives, structured message before signing, no free keypair manipulation | Done | SDK hashing/ECDSA/RIPEMD only (bech32 and DER encoders are hand-written but contain no secrets); private keys are zeroised on drop by the SDK; documents must have the Amino `StdSignDoc` structure (arbitrary JSON is refused). |
| Deliverables | Executive summary, findings, checklist appendix | n/a | Produced by the auditor. |

## Deliverables checklist (to be completed by the auditor)

- [ ] AI-based review performed and findings reviewed
- [ ] Review accounts for the blockchain protocol (clear signing, dangerous flows)
- [ ] Cryptographic primitives correctly used
- [ ] Flags, derivation paths and curves correct
- [ ] Clear signing displays information and asks for confirmation
- [ ] Blind signing disabled or non-existent (non-existent here)
- [ ] Workflow secure; snapshots cover nominal and error cases
- [ ] Boilerplate / SDK used to compile; no errors or warnings
- [ ] Guidelines enforcer and build workflows integrated and passing
- [ ] Unit, functional and fuzzing tests pass
- [ ] clippy clean; `cargo-audit` clean
- [ ] No medium or high severity vulnerabilities
- [ ] Technical and logical vulnerabilities reviewed
- [ ] Secrets erased, not exported or shown
- [ ] User-supplied messages validated before signing
- [ ] No re-implemented primitives that exist in the OS/SDK
- [ ] Client cannot freely manipulate the device keypairs
