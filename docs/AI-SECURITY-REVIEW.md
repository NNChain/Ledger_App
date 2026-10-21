# AI-assisted security review (developer side)

Method: Ledger's `SECURITY.REVIEW.md` skill (phases 0 to 10), applied by an LLM to version 0.1.0,
with the blockchain protocol context below, then confirmed with tests. **The external auditor must
repeat this review independently**; this document is a starting point and an evidence trail.

* Scope: all of `src/` (about 1,100 lines of Rust, no `unsafe`, no C).
* Archetype: account-based, **non-EVM** (Cosmos SDK Amino JSON signer).
* Protocol context: Cosmos SDK 0.53 chain; the signature covers `SHA-256(Amino StdSignDoc JSON)`; the
  chain rebuilds the same canonical JSON from the transaction and verifies the signature; messages are
  `{type, value}` pairs (bank send, staking, gov, CosmWasm, IBC, `nncore.tokenfactory` messages).

## Phase 0: architecture and APDU map

| INS | Name | P1 / P2 | Handler | Stateful | Confirmation | Multi-chunk | Risk |
|-----|------|---------|---------|----------|--------------|-------------|------|
| 0x00 | GET_VERSION | 0 / 0 | `get_version.rs` | no (ends a session) | none | no | Low |
| 0x04 | GET_ADDR | 0,1 / 0 | `get_addr.rs` | no (ends a session) | P1=1 shows address | no | Low |
| 0x02 | SIGN | 0,1,2 / 0 | `sign.rs` | **yes** | **always** | INIT/ADD/LAST | **High** |

No swap/library mode, no plugins, no PKI, no NVM settings, no blind signing, no custom crypto.

## Phase 1: trust model

Trusted: Ledger OS, SDK. Untrusted: host and every APDU byte, and the whole content of the sign doc.
The attacker can send any APDU sequence in any order. Privileges: `flags=0`, curve `secp256k1` only,
path restricted to `44'/118'`.

## Phase 2: dispatcher

* Typed `Instruction` enum built in `TryFrom<ApduHeader>`: invalid P1/P2 → `0x6B00`, unknown INS →
  `0x6D00`, wrong CLA → rejected by the SDK (`set_expected_cla(0x55)`).
* Malformed data returns a status word; the 3,000-APDU random fuzz and the 250-mutation document fuzz
  never crashed or hung the app.

## Phase 3: state and memory

* Global state: one `TxContext` (`buf`, `path`, `started`, `finished`). No static buffers, no unions.
* State machine: INIT resets everything; ADD/LAST need `started`; every LAST outcome (approve, reject,
  error) wipes the buffer and path; **any other command ends the session**; oversize aborts the session.
  Tests: `test_session_state_is_wiped_after_signing`, `test_reinit_discards_previous_chunks`,
  `test_other_commands_end_the_signing_session`.
* Memory: heap is bounded by hard limits (3072 bytes document, 80 values, 3072 display bytes, 28 KiB heap);
  worst-case shapes are exercised on the emulator.

## Phase 4: vulnerability hunting

| Class | Result |
|-------|--------|
| Memory safety (OOB, overflow, truncation) | No `unsafe`. Indexing is bounds-checked by construction; casts reviewed (`as u8` on values ≤ 33/72/17). One integer overflow found and fixed (message index `n + 1` could wrap for a key such as `18446744073709551615`, now `saturating_add`). |
| Clear-signing bypass (critical class) | The signed bytes are the parsed bytes (`ctx.buf`), the UI blocks until a decision, no re-serialisation. Display spoofing found and fixed: bidi/zero-width/look-alike characters and an ambiguous backslash. Arbitrary JSON could be signed: fixed by requiring the Amino `StdSignDoc` structure. |
| Cryptography | SDK hashing and RFC 6979 ECDSA, low-S DER re-encoding verified against `k256`; private keys zeroised on drop by the SDK; fixed path rules; HRP never affects the key. |
| APDU protocol | Chunk order, replay, size, partial state: covered (Appendix B checklist items all enforced). |
| Code quality | 0 compiler warnings, clippy clean; constants named; functions short (largest is the JSON value parser). |

## Phase 5/6: reachability and false positives

All findings were reachable by APDU (SIGN, INIT/ADD/LAST). Dismissed as false positives: reported
"leak" patterns do not exist (no manual allocation); `Vec` growth is bounded by the length checks; the
hand-written bech32 and DER encoders hold no secrets.

## Phase 7: findings (all fixed, with regression tests)

Severity uses Ledger's scale. "Before fix" describes the state of the first internal build.

| ID | Before fix | Finding | CWE | Status |
|----|-----------|---------|-----|--------|
| R1 | HIGH | Any valid JSON could be signed (not only an Amino sign doc): a signing oracle for attacker-chosen content | CWE-345 | fixed: strict `StdSignDoc` structure (`flatten_sign_doc`) |
| R2 | HIGH | Display spoofing: non-ASCII look-alikes, bidi overrides, zero-width characters and an ambiguous backslash were shown raw | CWE-345 | fixed: all non-ASCII shown as `\u{…}`, control characters/DEL rejected, backslash doubled |
| R3 | WARNING | Heap exhaustion (availability): ~3.5 KB / 65 values, then ~4 KB / 80 values, crashed the app; a small deeply nested document expanded labels | CWE-770 | fixed: per-item memory slimmed, hard limits, 28 KiB heap |
| R4 | WARNING | Stale session state; a session could continue across other commands | CWE-362 | fixed |
| R5 | WARNING | Integer overflow in message-index label | CWE-190 | fixed |
| R6 | WARNING | Lax JSON number grammar; DER reader accepted negative/non-minimal integers and trailing bytes; coin merging joined non-coin leaves | CWE-20 | fixed (found by differential fuzzing) |
| R7 | INFO | cosmjs asks the public key with HRP `cosmos`; unused import and a clippy lint; SDK dependency not pinned | n/a | fixed |

Note on R1: while implementing the fix, the new fuzz test found that an empty object (`{}`) bypassed the
structure check through the parser's empty-object shortcut. It was fixed before any release and is covered
by `sign_doc_shape_rejects_everything_else`.

APDU exploitability: R1, R2 direct and unguarded (user approval still required); R3 to R7 availability or
hardening. No CRITICAL or HIGH finding remains.

## Phase 8: PoC / confirmation evidence

* Host (x86): differential fuzzing against `serde_json` and `k256`, 10 tests, about 2 million inputs.
* Device (Speculos, Flex and Stax): functional and audit suites including a fuzz of 250 mutated documents,
  3,000 random APDUs, worst-case size shapes, and snapshot comparison of all review flows.

## Phase 9: coherence check

| Pair | Result |
|------|--------|
| Code ↔ docs | `docs/APDU.md` lists INS, P1/P2, status words and limits as implemented |
| Code ↔ tests | every handler and every status word has a test; error paths and user rejection covered |
| Test quality | both devices have functional tests; screens verified with snapshots; boundary values tested |

## Verdict (developer's own)

No reachable CRITICAL or HIGH findings after the fixes above. Remaining observations: generic display
(no denomination formatting, no message allow-list), document limits (3 KB / 80 values), `118` coin type
shared with the Cosmos app, Nano devices unsupported.
