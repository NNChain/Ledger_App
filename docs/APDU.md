# NNChain Ledger app: APDU specification

The app implements the **same wire protocol as the Ledger Cosmos app (Zondax)** so existing Cosmos
clients (cosmjs `LedgerSigner`, `ledger-cosmos-js`) work unchanged. It differs in what it *accepts*
(see "Restrictions"). Supported devices: Ledger Stax and Flex (NBGL touch UI), SDK `ledger_device_sdk`
1.42.x, API level 27.

All commands use `CLA = 0x55`. Any other CLA is answered by the SDK with `0x6E00`.
Multi-byte integers in the key path are **little endian**.

| INS  | Name        | P1                          | P2   | Data |
|------|-------------|-----------------------------|------|------|
| 0x00 | GET_VERSION | 0                           | 0    | none |
| 0x04 | GET_ADDR    | 0 = return, 1 = show + confirm | 0 | `hrp_len(1) ‖ hrp ‖ path(20)` |
| 0x02 | SIGN        | 0 = INIT, 1 = ADD, 2 = LAST | 0 (JSON) | see below |

The application name / version for the dashboard (`CLA 0xB0, INS 0x01`) is answered by the OS from the
app metadata (`NNChain`, `0.1.0`).

## GET_VERSION
Reply: `test_mode(1)=0 ‖ major(1) ‖ minor(1) ‖ patch(1) ‖ locked(1)=0`.

## GET_ADDR
* `path` = five u32 LE words: `44'`, `118'`, `account'`, `0`, `index` (see "Key path").
* `hrp` (3..83 bytes) is accepted for client compatibility (cosmjs asks with `"cosmos"`) but the app
  **always** produces and displays the `nnc` address.
* Reply: `compressed_pubkey(33) ‖ bech32_address(ASCII, "nnc1…")`.
* P1 = 1 shows the address on screen and requires the user to confirm; rejection returns `0x6986`.
* Address = `bech32("nnc", RIPEMD160(SHA256(compressed_pubkey)))`.

## SIGN (Amino JSON mode, P2 = 0)
1. **INIT** (P1 = 0): data = `path(20)` optionally followed by `hrp_len(1) ‖ "nnc"`. Resets any previous session.
2. **ADD** (P1 = 1): data = next chunk of the sign doc (≤ 255 bytes; clients use 250).
3. **LAST** (P1 = 2): final chunk. The device:
   1. appends the chunk, parses the **complete** buffer with the strict JSON parser (`json_view.rs`) and
      requires the structure of an Amino `StdSignDoc`: top-level keys exactly `account_number`, `chain_id`,
      `fee` (object), `memo`, `msgs` (non-empty array of `{type: string, value: object}`), `sequence`
      (+ optional `timeout_height`); anything else is refused with `0x6984`,
   2. shows every leaf value on the review screen,
   3. waits for the user (Tap to continue / swipe / **Hold to sign**),
   4. on approval signs `SHA-256(buffer)` with ECDSA/secp256k1 (RFC 6979), normalises to low-S, returns the
      **DER** signature (≤ 72 bytes); on rejection returns `0x6986`.
4. After LAST (any outcome) the buffer, path and session flag are wiped; ADD/LAST without a new INIT → `0x6984`.
   Any other command (GET_VERSION, GET_ADDR) received during a session also ends it.

The signed bytes are exactly the bytes that were parsed and displayed (same buffer, no re-serialisation).
P2 = 1 (SIGN_MODE_TEXTUAL) is **not** supported (`0x6B00`).

### Key path
`m/44'/118'/account'/0/index`: purpose, coin type and account are hardened, change must be `0`, index
non-hardened. Anything else → `0x6A81`. The manifest (`package.metadata.ledger.path`) restricts the app to
`44'/118'` at OS level as well.

## Status words
| SW | Meaning |
|----|---------|
| 0x9000 | OK |
| 0x6986 | User rejected |
| 0x6984 | Data invalid (not strict JSON, no INIT, limits exceeded) |
| 0x6700 | Wrong data length |
| 0x6B00 | Wrong P1/P2 |
| 0x6D00 | INS not supported |
| 0x6E00 | CLA not supported |
| 0x6A81 | Path not allowed |
| 0x6A82 | Wrong HRP in SIGN INIT (GET_ADDR never fails on HRP) |
| 0x6A83 | Sign doc larger than 3072 bytes |
| 0xB006/0xB008/0xB009 | Hash / sign / key derivation failure |

## Limits
* Sign doc: ≤ 3072 bytes. JSON nesting ≤ 16. ≤ 80 displayed values. ≤ 3072 total displayed bytes
  (labels + values). A doc that exceeds a limit is refused with `0x6984` (parser limits) or `0x6A83` (size).
* Heap: 28 KiB (`HEAP_SIZE`, `.cargo/config.toml`).
* Right after a review/status screen the device may answer `0x6901` (busy) for about a second; clients retry.
