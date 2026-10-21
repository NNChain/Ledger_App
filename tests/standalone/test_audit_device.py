"""Audit-oriented on-device tests (run on Speculos): protocol fuzzing, session isolation,
"no signature without approval" and heap stress.

Run:  pytest tests/test_audit_device.py --device flex -q
"""
import hashlib
import json
import random
import time

import pytest
from ragger.error import ExceptionRAPDU

from test_nnchain import (
    CLA, INS_ADDR, INS_SIGN, INS_VERSION, SW_DATA_INVALID,
    addr_data, canonical, check_sig, chunks_for, get_pubkey, path_bytes, send_doc,
)


SW_BUSY = 0x6901  # standard Ledger "device busy": a status screen is still being shown


def xchg(backend, ins, p1, p2, data=b""):
    """exchange() that retries while the device is busy showing a status screen,
    as real Ledger clients do."""
    for _ in range(40):
        try:
            return backend.exchange(CLA, ins, p1, p2, data)
        except ExceptionRAPDU as e:
            if e.status != SW_BUSY:
                raise
            wait_home(backend)
    raise AssertionError("device stayed busy")


def wait_home(backend, timeout=10.0):
    """Waits until the app's home screen is shown again. Status screens ("Transaction
    rejected"...) are dismissed with a tap: the emulator has no auto-dismiss timer."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        txt = screen_text(backend)
        if "enables signing" in txt:
            return
        if any(k in txt for k in ("rejected", "signed", "confirmed", "approved", "cancelled")):
            backend.finger_touch(240, 300, 0.1)
        time.sleep(0.2)
    raise AssertionError("home screen did not come back: " + screen_text(backend))


REVIEW_MARKERS = ("Review NNChain", "Reject", "Tap to continue")


def alive(backend):
    r = xchg(backend, INS_VERSION, 0, 0, b"")
    assert len(r.data) == 5


def screen_text(backend):
    content = backend.get_current_screen_content()  # {"events": [{"text": ..., "x": ...}, ...]}
    return " | ".join(e.get("text", "") for e in content.get("events", []))


def on_review_screen(backend, timeout=2.5):
    """Polls until the review screen is displayed (the device needs a moment to draw it).
    Returns False if nothing shows up, i.e. the APDU was rejected before any UI."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(m in screen_text(backend) for m in REVIEW_MARKERS):
            return True
        time.sleep(0.1)
    return False


def python_json_valid(doc: bytes) -> bool:
    """Loose reference: Python accepts a superset of what the device accepts."""
    try:
        json.loads(doc.decode("utf-8"))
        return True
    except Exception:
        return False


def sign_and_reject(backend, scenario_navigator, doc_bytes):
    """Sends a full doc; if the device opens the review screen, rejects it.
    Returns the status word (0x9000 would mean it was signed without approval)."""
    wait_home(backend)
    ch = chunks_for(doc_bytes)
    for i, c in enumerate(ch[:-1]):
        xchg(backend, INS_SIGN, 0 if i == 0 else 1, 0, c)
    expect_review = python_json_valid(doc_bytes)
    try:
        with backend.exchange_async(CLA, INS_SIGN, 2, 0, ch[-1]):
            shown = on_review_screen(backend, timeout=2.5 if expect_review else 0.4)
            if shown:
                assert expect_review, "device opened a review for a doc the reference parser rejects"
                scenario_navigator.review_reject(do_comparison=False)
    except ExceptionRAPDU as e:
        return e.status
    return 0x9000


# ----------------------------------------------------------------------------- fuzzing

def test_random_apdu_fuzz_never_crashes(backend):
    """Random CLA-0x55 APDUs (never a valid LAST/SHOW that would wait for the user)."""
    rng = random.Random(1234)
    for n in range(3000):
        ins = rng.choice([0x00, 0x02, 0x04, 0x01, 0x03, 0x05, rng.randrange(256)])
        p1 = rng.choice([0, 1, 2, 3, rng.randrange(256)])
        p2 = rng.choice([0, 1, rng.randrange(256)])
        data = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 3, 20, 24, 25, 60, 200, 255])))
        if ins == 0x04 and p1 == 1:
            continue  # "show address" waits for the user when the payload is valid
        if ins == 0x02 and p1 == 2:
            data = (b"\x00" + data)[:255]  # NUL byte: can never be a valid doc, so it is rejected at once
        try:
            backend.exchange(CLA, ins, p1, p2, data)
        except ExceptionRAPDU:
            pass
        if n % 250 == 0:
            alive(backend)
    alive(backend)


def test_wrong_cla_is_refused(backend):
    for cla in (0x00, 0x80, 0xB0, 0xE0, 0x54, 0x56, 0xFF):
        try:
            r = backend.exchange(cla, INS_VERSION, 0, 0, b"")
            assert cla == 0xB0  # only the OS dashboard class may answer
        except ExceptionRAPDU as e:
            assert e.status in (0x6E00, 0x6D00, 0x6E01)
    alive(backend)


def test_mutated_docs_fuzz(backend, scenario_navigator):
    """Mutated valid sign docs: each is either rejected immediately or reaches the review
    screen (then rejected by the test); the app must stay alive and never sign."""
    rng = random.Random(77)
    base = canonical(send_doc(memo="fuzz"))
    results = {"invalid": 0, "reviewed": 0}
    for n in range(250):
        b = bytearray(base)
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(4)
            if not b:
                break
            i = rng.randrange(len(b))
            if op == 0:
                b[i] = rng.randrange(256)
            elif op == 1:
                del b[i]
            elif op == 2:
                b.insert(i, rng.choice(b'{}[]":,\\ 0e-+.tfnu'))
            else:
                b = b[: rng.randrange(1, len(b))] if len(b) > 1 else b
        sw = sign_and_reject(backend, scenario_navigator, bytes(b))
        assert sw != 0x9000, "a fuzzed doc must never be signed without approval"
        results["invalid" if sw == SW_DATA_INVALID else "reviewed"] += 1
        if n % 50 == 0:
            alive(backend)
    alive(backend)
    assert results["invalid"] > 20


# ------------------------------------------------------------------ approval / session

def test_no_signature_without_user_approval(backend, scenario_navigator):
    """While the review is open the device must not answer; rejecting yields 0x6986."""
    doc = canonical(send_doc())
    ch = chunks_for(doc)
    for i, c in enumerate(ch[:-1]):
        xchg(backend, INS_SIGN, 0 if i == 0 else 1, 0, c)
    with pytest.raises(ExceptionRAPDU) as e:
        with backend.exchange_async(CLA, INS_SIGN, 2, 0, ch[-1]):
            assert on_review_screen(backend), "review must be on screen before any signature"
            scenario_navigator.review_reject(do_comparison=False)
    assert e.value.status == 0x6986
    # after the reject nothing is signable any more without a new INIT
    with pytest.raises(ExceptionRAPDU) as e2:
        xchg(backend, INS_SIGN, 2, 0, ch[-1])
    assert e2.value.status == SW_DATA_INVALID


def test_session_state_is_wiped_after_signing(backend, scenario_navigator):
    pk, _ = get_pubkey(backend)
    doc = canonical(send_doc())
    ch = chunks_for(doc)
    for i, c in enumerate(ch[:-1]):
        xchg(backend, INS_SIGN, 0 if i == 0 else 1, 0, c)
    with backend.exchange_async(CLA, INS_SIGN, 2, 0, ch[-1]):
        scenario_navigator.review_approve(do_comparison=False)
    check_sig(pk, doc, bytes(backend.last_async_response.data))
    for p1 in (1, 2):
        with pytest.raises(ExceptionRAPDU) as e:
            xchg(backend, INS_SIGN, p1, 0, b'{"a":1}')
        assert e.value.status == SW_DATA_INVALID
    alive(backend)


def test_reinit_discards_previous_chunks(backend, scenario_navigator):
    """Chunks sent before a second INIT must not leak into the document that is signed."""
    pk, _ = get_pubkey(backend)
    stale = canonical(send_doc(memo="STALE-" + "z" * 300))
    fresh = canonical(send_doc(memo="fresh"))
    sc = chunks_for(stale)
    xchg(backend, INS_SIGN, 0, 0, sc[0])
    xchg(backend, INS_SIGN, 1, 0, sc[1])  # leave a partial doc behind
    ch = chunks_for(fresh)
    for i, c in enumerate(ch[:-1]):
        xchg(backend, INS_SIGN, 0 if i == 0 else 1, 0, c)
    with backend.exchange_async(CLA, INS_SIGN, 2, 0, ch[-1]):
        scenario_navigator.review_approve(do_comparison=False)
    check_sig(pk, fresh, bytes(backend.last_async_response.data))  # sha256 over `fresh` only


def test_signature_uses_requested_account_key(backend, scenario_navigator):
    pk1, _ = get_pubkey(backend, account=1, index=3)
    doc = canonical(send_doc(memo="acct1"))
    ch = chunks_for(doc, path=path_bytes(account=1, index=3))
    for i, c in enumerate(ch[:-1]):
        xchg(backend, INS_SIGN, 0 if i == 0 else 1, 0, c)
    with backend.exchange_async(CLA, INS_SIGN, 2, 0, ch[-1]):
        scenario_navigator.review_approve(do_comparison=False)
    check_sig(pk1, doc, bytes(backend.last_async_response.data))


def test_hrp_in_sign_init_is_checked(backend):
    bad = path_bytes() + bytes([6]) + b"cosmos"
    with pytest.raises(ExceptionRAPDU) as e:
        xchg(backend, INS_SIGN, 0, 0, bad)
    assert e.value.status == 0x6A82
    ok = path_bytes() + bytes([3]) + b"nnc"
    xchg(backend, INS_SIGN, 0, 0, ok)


# ------------------------------------------------------------------------ resources

def big_doc(items, pad):
    msgs = [
        {
            "type": "cosmos-sdk/MsgSend",
            "value": {
                "amount": [{"amount": str(i), "denom": "nnc"}],
                "from_address": "nnc1qwk8n4v3faduqmkcgq7uh4ufgx050hc83wc5rh",
                "to_address": "nnc1qn4f9f45wf2u8gs3nzqws2d2gm8gjtgh4zqnc6",
                "memo_%d" % i: "p" * pad,
            },
        }
        for i in range(items)
    ]
    return canonical(send_doc(msgs=msgs))


@pytest.mark.parametrize("items,pad", [(3, 100), (6, 40), (9, 8)])
def test_large_docs_do_not_exhaust_the_heap(backend, scenario_navigator, items, pad):
    doc = big_doc(items, pad)
    assert len(doc) <= 3072, len(doc)
    sw = sign_and_reject(backend, scenario_navigator, doc)
    assert sw in (0x6986, SW_DATA_INVALID, 0x6A83), hex(sw)
    alive(backend)  # a heap panic would terminate the app here


def test_oversize_doc_is_refused_cleanly(backend):
    doc = canonical(send_doc(memo="m" * 4500))
    ch = chunks_for(doc)
    xchg(backend, INS_SIGN, 0, 0, ch[0])
    with pytest.raises(ExceptionRAPDU) as e:
        for c in ch[1:]:
            xchg(backend, INS_SIGN, 1, 0, c)
    assert e.value.status == 0x6A83
    alive(backend)


def test_repeated_sessions_do_not_leak(backend, scenario_navigator):
    doc = canonical(send_doc(memo="leak-check " + "q" * 400))
    for _ in range(40):
        assert sign_and_reject(backend, scenario_navigator, doc) == 0x6986
    alive(backend)


def test_label_amplification_doc_is_refused_not_crashing(backend, scenario_navigator):
    """A small, deeply nested doc whose labels would expand to far more display text than
    the heap can hold must be refused cleanly."""
    nested = "".join('{"abcdefghij":' for _ in range(15)) + "[" + ",".join("1" for _ in range(80)) + "]" + "}" * 15
    assert len(nested) < 1000
    assert sign_and_reject(backend, scenario_navigator, nested.encode()) == SW_DATA_INVALID
    alive(backend)


def shape_doc(kind):
    """Documents at the edge of the limits, in the three shapes that stress memory differently."""
    if kind == "many_small_fields":      # 77 displayed values, tiny doc: per-field overhead dominates
        msgs = [{"type": "x/MsgMany", "value": {"n": list(range(70))}}]
        return canonical(send_doc(msgs=msgs))
    if kind == "one_big_value":          # ~2.9 KB of text in one field: text copies dominate
        return canonical(send_doc(memo="m" * 2450))
    if kind == "mixed":                  # ~60 fields filling most of the byte budget
        msgs = [{"type": "x/MsgMixed",
                 "value": {"f%02d" % i: "v" * 36 for i in range(55)}}]
        return canonical(send_doc(msgs=msgs))
    raise ValueError(kind)


@pytest.mark.parametrize("kind", ["many_small_fields", "one_big_value", "mixed"])
def test_worst_case_docs_at_the_limits(backend, scenario_navigator, kind):
    """Docs at the size / field-count limits are reviewed (and here rejected) without crashing."""
    doc = shape_doc(kind)
    assert len(doc) <= 3072, len(doc)
    assert sign_and_reject(backend, scenario_navigator, doc) == 0x6986
    alive(backend)


def test_docs_over_the_field_limit_are_refused(backend, scenario_navigator):
    msgs = [{"type": "x/MsgMany", "value": {"n": list(range(90))}}]
    assert sign_and_reject(backend, scenario_navigator, canonical(send_doc(msgs=msgs))) == SW_DATA_INVALID
    alive(backend)


@pytest.mark.parametrize("kind", ["many_small_fields", "one_big_value"])
def test_signing_works_at_the_limits(backend, scenario_navigator, kind):
    """Approve and sign documents at the limits: the signature must still verify."""
    pk, _ = get_pubkey(backend)
    wait_home(backend)
    doc = shape_doc(kind)
    ch = chunks_for(doc)
    for i, c in enumerate(ch[:-1]):
        xchg(backend, INS_SIGN, 0 if i == 0 else 1, 0, c)
    with backend.exchange_async(CLA, INS_SIGN, 2, 0, ch[-1]):
        scenario_navigator.review_approve(do_comparison=False)
    check_sig(pk, doc, bytes(backend.last_async_response.data))
    wait_home(backend)
    alive(backend)


# --------------------------------------------------------------- structure / state machine

@pytest.mark.parametrize("doc", [
    b'{"foo":"bar"}',
    b'{}',
    b'[]',
    b'"just a string"',
    b'{"account_number":"1","chain_id":"c","fee":{},"memo":"","msgs":[],"sequence":"1"}',          # no msgs
    b'{"account_number":"1","chain_id":"c","fee":{},"memo":"","msgs":[{"a":1}],"sequence":"1"}',   # bad msg
    b'{"account_number":1,"chain_id":"c","fee":{},"memo":"","msgs":[{"type":"t","value":{}}],"sequence":"1"}',
])
def test_non_sign_doc_json_is_refused(backend, scenario_navigator, doc):
    """Valid JSON that is not an Amino sign doc must never reach the review screen."""
    assert sign_and_reject(backend, scenario_navigator, doc) == SW_DATA_INVALID
    alive(backend)


@pytest.mark.parametrize("interrupt", ["version", "address"])
def test_other_commands_end_the_signing_session(backend, interrupt):
    doc = canonical(send_doc())
    ch = chunks_for(doc)
    for i, c in enumerate(ch[:-1]):
        xchg(backend, INS_SIGN, 0 if i == 0 else 1, 0, c)
    if interrupt == "version":
        xchg(backend, INS_VERSION, 0, 0, b"")
    else:
        xchg(backend, INS_ADDR, 0, 0, addr_data())
    with pytest.raises(ExceptionRAPDU) as e:
        xchg(backend, INS_SIGN, 2, 0, ch[-1])
    assert e.value.status == SW_DATA_INVALID
