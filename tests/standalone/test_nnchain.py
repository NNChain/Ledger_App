import hashlib
import json
import struct

import pytest
from Crypto.Hash import RIPEMD160
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der
from bip_utils import Bech32Encoder
from ragger.error import ExceptionRAPDU

CLA = 0x55
INS_VERSION, INS_SIGN, INS_ADDR = 0x00, 0x02, 0x04
SECP_N = SECP256k1.order
HARD = 0x80000000

SW_DENY = 0x6986
SW_DATA_INVALID = 0x6984
SW_BAD_PATH = 0x6A81
SW_BAD_HRP = 0x6A82
SW_TOO_LARGE = 0x6A83


def path_bytes(coin=118, account=0, change=0, index=0):
    return struct.pack("<5I", 44 | HARD, coin | HARD, account | HARD, change, index)


def addr_data(hrp="nnc", **kw):
    return bytes([len(hrp)]) + hrp.encode() + path_bytes(**kw)


def expected_address(compressed_pk: bytes) -> str:
    sha = hashlib.sha256(compressed_pk).digest()
    rip = RIPEMD160.new(sha).digest()
    return Bech32Encoder.Encode("nnc", rip)


def canonical(doc) -> bytes:
    """Amino canonical JSON as produced by cosmjs serializeSignDoc."""
    s = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode()


def send_doc(memo="", msgs=None, sequence="7"):
    msgs = msgs or [
        {
            "type": "cosmos-sdk/MsgSend",
            "value": {
                "amount": [{"amount": "1000000", "denom": "nnc"}],
                "from_address": "nnc1qwk8n4v3faduqmkcgq7uh4ufgx050hc83wc5rh",
                "to_address": "nnc1qn4f9f45wf2u8gs3nzqws2d2gm8gjtgh4zqnc6",
            },
        }
    ]
    return {
        "account_number": "12",
        "chain_id": "nnchain-mainnet-1",
        "fee": {"amount": [{"amount": "12500", "denom": "nnc"}], "gas": "500000"},
        "memo": memo,
        "msgs": msgs,
        "sequence": sequence,
    }


def get_pubkey(backend, **kw):
    r = backend.exchange(CLA, INS_ADDR, 0, 0, addr_data(**kw))
    return bytes(r.data[:33]), bytes(r.data[33:]).decode()


def chunks_for(doc_bytes, path=None, size=250):
    first = path if path is not None else path_bytes()
    out = [first]
    for i in range(0, len(doc_bytes), size):
        out.append(doc_bytes[i : i + size])
    return out


def sign(backend, doc_bytes, navigate):
    """Sends INIT/ADD/LAST; `navigate` is called while the last chunk awaits approval."""
    ch = chunks_for(doc_bytes)
    for i, c in enumerate(ch[:-1]):
        p1 = 0 if i == 0 else 1
        backend.exchange(CLA, INS_SIGN, p1, 0, c)
    with backend.exchange_async(CLA, INS_SIGN, 2 if len(ch) > 1 else 0, 0, ch[-1]):
        navigate()
    return backend.last_async_response


def send_all_but_last(backend, doc_bytes):
    ch = chunks_for(doc_bytes)
    for i, c in enumerate(ch[:-1]):
        backend.exchange(CLA, INS_SIGN, 0 if i == 0 else 1, 0, c)
    return ch[-1]


def check_sig(pubkey, doc_bytes, der):
    vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
    from ecdsa.util import sigdecode_der as dec

    r, s = dec(der, SECP_N)
    assert s <= SECP_N // 2, "signature must be low-S"
    assert vk.verify_digest(der, hashlib.sha256(doc_bytes).digest(), sigdecode=sigdecode_der)


def test_version(backend):
    r = backend.exchange(CLA, INS_VERSION, 0, 0, b"")
    assert len(r.data) == 5
    assert r.data[0] == 0  # not test mode
    assert tuple(r.data[1:4]) == (0, 1, 0)


def test_get_address(backend):
    pk, addr = get_pubkey(backend)
    assert len(pk) == 33 and pk[0] in (2, 3)
    assert addr.startswith("nnc1")
    assert addr == expected_address(pk)


def test_addresses_differ_per_index(backend):
    _, a0 = get_pubkey(backend, index=0)
    _, a1 = get_pubkey(backend, index=1)
    assert a0 != a1


def test_other_hrp_still_returns_nnc_address(backend):
    # cosmjs asks for the pubkey with HRP "cosmos"; the app must never emit it.
    r = backend.exchange(CLA, INS_ADDR, 0, 0, addr_data(hrp="cosmos"))
    assert bytes(r.data[33:]).decode().startswith("nnc1")


def test_rejects_other_coin_type(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, INS_ADDR, 0, 0, addr_data(coin=60))
    assert e.value.status == SW_BAD_PATH


def test_show_address(backend, scenario_navigator):
    with backend.exchange_async(CLA, INS_ADDR, 1, 0, addr_data()):
        scenario_navigator.address_review_approve()
    r = backend.last_async_response
    assert bytes(r.data[33:]).decode().startswith("nnc1")


def test_show_address_reject(backend, scenario_navigator):
    with pytest.raises(ExceptionRAPDU) as e:
        with backend.exchange_async(CLA, INS_ADDR, 1, 0, addr_data()):
            scenario_navigator.address_review_reject()
    assert e.value.status == SW_DENY


def test_sign_send(backend, scenario_navigator):
    pk, _ = get_pubkey(backend)
    doc = canonical(send_doc())
    r = sign(backend, doc, lambda: scenario_navigator.review_approve())
    check_sig(pk, doc, bytes(r.data))


def test_sign_reject(backend, scenario_navigator):
    doc = canonical(send_doc())
    last = send_all_but_last(backend, doc)
    with pytest.raises(ExceptionRAPDU) as e:
        with backend.exchange_async(CLA, INS_SIGN, 2, 0, last):
            scenario_navigator.review_reject()
    assert e.value.status == SW_DENY


def test_sign_multi_chunk_long_memo(backend, scenario_navigator):
    pk, _ = get_pubkey(backend)
    doc = canonical(send_doc(memo="order-" + "x" * 700))
    assert len(doc) > 500
    r = sign(backend, doc, lambda: scenario_navigator.review_approve())
    check_sig(pk, doc, bytes(r.data))


def test_sign_escaped_chars(backend, scenario_navigator):
    pk, _ = get_pubkey(backend)
    doc = canonical(send_doc(memo="a<b>&c"))
    assert b"\\u003c" in doc
    r = sign(backend, doc, lambda: scenario_navigator.review_approve())
    check_sig(pk, doc, bytes(r.data))


def test_sign_tokenfactory_mint(backend, scenario_navigator):
    pk, _ = get_pubkey(backend)
    msgs = [
        {
            "type": "nncore/x/tokenfactory/MsgMintAndSendTokens",
            "value": {
                "authority": "nnc1qwk8n4v3faduqmkcgq7uh4ufgx050hc83wc5rh",
                "denom": "factory/nnc1qwk8n4v3faduqmkcgq7uh4ufgx050hc83wc5rh/nusd",
                "amount": "1000000",
                "recipient": "nnc1qn4f9f45wf2u8gs3nzqws2d2gm8gjtgh4zqnc6",
            },
        }
    ]
    doc = canonical(send_doc(msgs=msgs))
    r = sign(backend, doc, lambda: scenario_navigator.review_approve())
    check_sig(pk, doc, bytes(r.data))


def test_sign_wasm_execute_nested(backend, scenario_navigator):
    pk, _ = get_pubkey(backend)
    msgs = [
        {
            "type": "wasm/MsgExecuteContract",
            "value": {
                "contract": "nnc14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9sc4f4zp",
                "funds": [{"amount": "5", "denom": "nnc"}],
                "msg": {"swap": {"min_out": "1", "path": ["a", "b"], "deadline": None, "flag": True}},
                "sender": "nnc1qwk8n4v3faduqmkcgq7uh4ufgx050hc83wc5rh",
            },
        }
    ]
    doc = canonical(send_doc(msgs=msgs))
    r = sign(backend, doc, lambda: scenario_navigator.review_approve())
    check_sig(pk, doc, bytes(r.data))


def test_sign_rejects_invalid_json(backend):
    last = send_all_but_last(backend, b'{"chain_id":"x", broken')
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, INS_SIGN, 2, 0, last)
    assert e.value.status == SW_DATA_INVALID


def test_sign_rejects_trailing_garbage(backend):
    doc = canonical(send_doc()) + b"x"
    last = send_all_but_last(backend, doc)
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, INS_SIGN, 2, 0, last)
    assert e.value.status == SW_DATA_INVALID


def test_sign_rejects_wrong_path(backend):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, INS_SIGN, 0, 0, path_bytes(coin=60))
    assert e.value.status == SW_BAD_PATH


def test_sign_rejects_oversize(backend):
    backend.exchange(CLA, INS_SIGN, 0, 0, path_bytes())
    with pytest.raises(ExceptionRAPDU) as e:
        for _ in range(30):
            backend.exchange(CLA, INS_SIGN, 1, 0, b"a" * 250)
    assert e.value.status == SW_TOO_LARGE
