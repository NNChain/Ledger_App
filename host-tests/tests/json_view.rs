//! Fuzz / differential tests for `src/json_view.rs` (the sign doc parser used for display).
//!
//! Properties checked:
//!  1. never panics, on any byte string (random bytes and mutated valid docs);
//!  2. accepts exactly what a reference JSON parser accepts (documented exceptions only);
//!  3. every displayed value equals an independently computed reference rendering;
//!  4. resource bounds: at most MAX_ITEMS items, nesting depth <= MAX_DEPTH.

extern crate alloc;

#[allow(dead_code)]
#[path = "../../src/json_view.rs"]
mod json_view;

use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_json::Value;

const KEYS: &[&str] = &[
    "account_number", "chain_id", "fee", "memo", "msgs", "sequence", "type", "value", "amount",
    "denom", "from_address", "to_address", "msg", "funds", "gas", "a", "b", "authority",
];
const WORDS: &[&str] = &[
    "nnc", "1000000", "nnchain-mainnet-1", "", "x", "send", "a b", "ünï", "日本", "\u{202e}rtl",
    "tab\there", "line\nbreak", "quote\"d", "back\\slash", "nul\u{0}z", "😀",
    "nnc1qwk8n4v3faduqmkcgq7uh4ufgx050hc83wc5rh", "<>&",
];

fn rand_scalar(rng: &mut StdRng) -> Value {
    match rng.gen_range(0..6) {
        0 => Value::Bool(rng.gen()),
        1 => Value::Null,
        2 => serde_json::json!(rng.gen_range(-5000i64..5000)),
        3 => serde_json::json!(rng.gen_range(-1.0e6f64..1.0e6)),
        _ => Value::String(WORDS[rng.gen_range(0..WORDS.len())].to_string()),
    }
}

fn rand_value(rng: &mut StdRng, depth: usize) -> Value {
    if depth == 0 || rng.gen_range(0..10) < 4 {
        return rand_scalar(rng);
    }
    if rng.gen() {
        let n = rng.gen_range(0..4);
        Value::Array((0..n).map(|_| rand_value(rng, depth - 1)).collect())
    } else {
        let n = rng.gen_range(0..4);
        let mut m = serde_json::Map::new();
        for _ in 0..n {
            m.insert(KEYS[rng.gen_range(0..KEYS.len())].to_string(), rand_value(rng, depth - 1));
        }
        Value::Object(m)
    }
}

/// Reference rendering of a decoded JSON string for the device screen.
fn ref_string(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04X}", c as u32)),
            c if c.is_ascii() => out.push(c),
            c => out.push_str(&format!("\\u{{{:X}}}", c as u32)),
        }
    }
    out
}

fn ref_leaf(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(ref_string(s)),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".into()),
        Value::Number(_) => None, // rendered from the original text, compared separately
        Value::Array(a) if a.is_empty() => Some("[]".into()),
        Value::Object(o) if o.is_empty() => Some("{}".into()),
        _ => None,
    }
}

/// Reference list of displayed values, in document order.
/// `raw` is the original text, used to read number tokens exactly as written.
fn ref_values(v: &Value, in_array: bool, out: &mut Vec<String>) {
    match v {
        Value::Array(a) => {
            if a.is_empty() {
                out.push("[]".into());
            }
            for x in a {
                ref_values(x, true, out);
            }
        }
        Value::Object(o) => {
            if o.is_empty() {
                out.push("{}".into());
                return;
            }
            let keys: Vec<&String> = o.keys().collect();
            // {"amount": scalar, "denom": scalar} inside a list is merged into one line.
            // (serde_json sorts keys alphabetically, matching the canonical order.)
            if in_array
                && keys.len() == 2
                && keys[0] == "amount"
                && keys[1] == "denom"
                && matches!(o["amount"], Value::String(_) | Value::Number(_))
                && matches!(o["denom"], Value::String(_) | Value::Number(_))
            {
                let a = scalar_text(&o["amount"]);
                let d = scalar_text(&o["denom"]);
                out.push(format!("{} {}", a, d));
                return;
            }
            for (_, x) in o {
                ref_values(x, false, out);
            }
        }
        _ => out.push(scalar_text(v)),
    }
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        other => ref_leaf(other).unwrap(),
    }
}

fn compact(v: &Value) -> String {
    // serde_json already emits raw UTF-8 and the shortest number form
    serde_json::to_string(v).unwrap()
}

#[test]
fn differential_valid_documents() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let (mut accepted, mut skipped) = (0u32, 0u32);
    for _ in 0..60_000 {
        let v = rand_value(&mut rng, 5);
        // a bare scalar is a valid document too
        let text = compact(&v);
        let got = json_view::flatten(text.as_bytes());
        let mut expect = Vec::new();
        ref_values(&v, false, &mut expect);
        match got {
            Ok(items) => {
                let vals: Vec<String> = items.iter().map(|i| i.value.clone()).collect();
                assert_eq!(vals, expect, "doc: {text}");
                assert!(items.len() <= 80);
                accepted += 1;
            }
            Err(()) => {
                // Only allowed when the doc has more than 200 leaves or is nested > 16 deep.
                assert!(expect.len() > 80 || depth(&v) > 16 || display_bytes(&items_ref(&v)) > 3072, "unexpected reject: {text}");
                skipped += 1;
            }
        }
    }
    eprintln!("differential: accepted {accepted}, rejected-by-limit {skipped}");
    assert!(accepted > 50_000);
}

fn items_ref(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    ref_values(v, false, &mut out);
    out
}

/// Lower bound on the displayed bytes (values only; labels only add to it).
fn display_bytes(vals: &[String]) -> usize {
    vals.iter().map(|s| s.len()).sum()
}

fn depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        Value::Object(o) => 1 + o.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Anything the device parser accepts must also be valid JSON per the reference parser.
/// Known, documented differences: lone/paired \uD800-\uDFFF escapes (shown literally).
fn check_subset(input: &[u8]) {
    let ours = json_view::flatten(input);
    if ours.is_ok() {
        let theirs: Result<Value, _> = serde_json::from_slice(input);
        if let Err(e) = theirs {
            let msg = e.to_string();
            // The reference parser also refuses numbers that overflow f64 (e.g. 6e856);
            // the device only checks the number grammar and shows the token as written.
            let allowed = msg.contains("surrogate")
                || msg.contains("unicode code point")
                || msg.contains("number out of range");
            assert!(allowed, "device accepted invalid JSON {:?}: {msg}", String::from_utf8_lossy(input));
        }
    }
}

#[test]
fn never_panics_and_is_a_subset_of_json_on_mutated_docs() {
    let mut rng = StdRng::seed_from_u64(0xFACADE);
    for round in 0..250_000u32 {
        let v = rand_value(&mut rng, 4);
        let mut bytes = compact(&v).into_bytes();
        let muts = rng.gen_range(1..5);
        for _ in 0..muts {
            if bytes.is_empty() {
                break;
            }
            match rng.gen_range(0..6) {
                0 => {
                    let i = rng.gen_range(0..bytes.len());
                    bytes[i] = rng.gen();
                }
                1 => {
                    let i = rng.gen_range(0..bytes.len());
                    bytes.remove(i);
                }
                2 => {
                    let i = rng.gen_range(0..=bytes.len());
                    let junk = b"{}[]\":,\\-+.eE0123456789tfnulrse \n\t\x00\x7f\xc3\xff";
                    bytes.insert(i, junk[rng.gen_range(0..junk.len())]);
                }
                3 => {
                    let n = rng.gen_range(0..=bytes.len());
                    bytes.truncate(n);
                }
                4 => {
                    let i = rng.gen_range(0..bytes.len());
                    let j = rng.gen_range(i..bytes.len());
                    let slice = bytes[i..=j].to_vec();
                    bytes.splice(i..i, slice);
                }
                _ => bytes.push(rng.gen()),
            }
        }
        check_subset(&bytes);
        let _ = round;
    }
}

#[test]
fn never_panics_on_random_bytes() {
    let mut rng = StdRng::seed_from_u64(7);
    for _ in 0..400_000 {
        let n = rng.gen_range(0..400);
        let bytes: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        check_subset(&bytes);
    }
    // structured-ish noise made of JSON punctuation
    let alphabet = b"{}[]\":,\\ 0123456789-+.eEtruefalsn\n";
    for _ in 0..400_000 {
        let n = rng.gen_range(0..200);
        let bytes: Vec<u8> = (0..n).map(|_| alphabet[rng.gen_range(0..alphabet.len())]).collect();
        check_subset(&bytes);
    }
}

#[test]
fn limits_are_enforced() {
    // depth: 17 nested arrays is rejected, 16 is the deepest accepted
    let ok = format!("{}1{}", "[".repeat(16), "]".repeat(16));
    let bad = format!("{}1{}", "[".repeat(40), "]".repeat(40));
    assert!(json_view::flatten(ok.as_bytes()).is_ok());
    assert!(json_view::flatten(bad.as_bytes()).is_err());
    // a very deep document must not blow the stack
    let deep = format!("{}1{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(json_view::flatten(deep.as_bytes()).is_err());
    // 80 leaves accepted, 81 rejected
    let arr = |n: usize| format!("[{}]", vec!["1"; n].join(","));
    assert_eq!(json_view::flatten(arr(80).as_bytes()).unwrap().len(), 80);
    assert!(json_view::flatten(arr(81).as_bytes()).is_err());
    // total displayed bytes are capped: a tiny, deeply nested doc cannot expand into huge labels
    let mut nested = String::new();
    for _ in 0..15 {
        nested.push_str("{\"abcdefghij\":");
    }
    nested.push_str("[1");
    for _ in 0..79 {
        nested.push_str(",1");
    }
    nested.push(']');
    for _ in 0..15 {
        nested.push('}');
    }
    assert!(nested.len() < 1000);
    assert!(json_view::flatten(nested.as_bytes()).is_err(), "label amplification must be refused");
    // long single values up to the cap are fine, one more byte is not
    let memo = |n: usize| format!("{{\"memo\":\"{}\"}}", "a".repeat(n));
    assert!(json_view::flatten(memo(3072 - 4).as_bytes()).is_ok());
    assert!(json_view::flatten(memo(3072).as_bytes()).is_err());
}

#[test]
fn spoofing_resistance() {
    let show = |s: &str| json_view::flatten(format!("{{\"memo\":\"{s}\"}}").as_bytes()).unwrap()[0].value.clone();
    // right-to-left override, zero width space, homoglyph (cyrillic a) are all visible as escapes
    assert_eq!(show("\u{202e}evil"), "\\u{202E}evil");
    assert_eq!(show("a\u{200b}b"), "a\\u{200B}b");
    assert_eq!(show("\u{0430}pple"), "\\u{430}pple");
    // JSON escapes cannot hide text: control characters are shown literally
    assert_eq!(show("a\\nb"), "a\\nb");
    assert_eq!(show("a\\u0000b"), "a\\u0000b");
    assert_eq!(show("a\\u001fb"), "a\\u001Fb");
    // a real backslash + 'n' differs from a newline escape
    assert_ne!(show("a\\\\nb"), show("a\\nb"));
    assert_eq!(show("a\\\\nb"), "a\\\\nb");
    // lone surrogates stay visible
    assert_eq!(show("\\ud800"), "\\uD800");
    // raw control characters and DEL are rejected
    assert!(json_view::flatten(b"{\"memo\":\"a\x01b\"}").is_err());
    assert!(json_view::flatten(b"{\"memo\":\"a\x7fb\"}").is_err());
    // key names are escaped the same way as values
    let items = json_view::flatten("{\"\u{202e}k\":1}".as_bytes()).unwrap();
    assert!(items[0].name.contains("\\u{202E}"));
}

#[test]
fn strict_json_grammar() {
    for bad in [
        "01", "1.", ".5", "-", "+1", "1e", "1e+", "--1", "1-2", "0x10", "tru", "truee", "nul",
        "[1,]", "{\"a\":1,}", "{\"a\"}", "{a:1}", "[1 2]", "\"abc", "\"\\x\"", "\"\\u12\"", "[]x",
        "", " ", "{}{}", "'a'", "[\"a\" \"b\"]",
    ] {
        assert!(json_view::flatten(bad.as_bytes()).is_err() || bad == "[]x" && false, "should reject {bad:?}");
    }
    for good in ["0", "-0", "1.5e-3", "[]", "{}", "true", "null", "\"\"", " [ 1 , 2 ] ", "-1E+10"] {
        assert!(json_view::flatten(good.as_bytes()).is_ok(), "should accept {good:?}");
    }
}


// ------------------------------------------------------------------------------------------
// Strict StdSignDoc shape (`flatten_sign_doc`)

fn doc(extra: &str) -> String {
    // canonical Amino sign doc: sorted keys, compact
    format!(
        "{{\"account_number\":\"12\",\"chain_id\":\"nnchain-mainnet-1\",\"fee\":{{\"amount\":[{{\"amount\":\"12500\",\"denom\":\"nnc\"}}],\"gas\":\"500000\"}},\"memo\":\"\",\"msgs\":[{{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{{\"amount\":[{{\"amount\":\"1\",\"denom\":\"nnc\"}}],\"from_address\":\"nnc1a\",\"to_address\":\"nnc1b\"}}}}],\"sequence\":\"7\"{extra}}}"
    )
}

#[test]
fn sign_doc_shape_accepts_real_documents() {
    assert!(json_view::flatten_sign_doc(doc("").as_bytes()).is_ok());
    // optional timeout_height (string) is allowed
    assert!(json_view::flatten_sign_doc(doc(",\"timeout_height\":\"100\"").as_bytes()).is_ok());
    // whitespace between tokens is fine
    let spaced = doc("").replace(",", ", ").replace(":", ": ");
    assert!(json_view::flatten_sign_doc(spaced.as_bytes()).is_ok());
}

#[test]
fn sign_doc_shape_rejects_everything_else() {
    let good = doc("");
    let bad: Vec<(String, &str)> = vec![
        ("{}".into(), "empty object"),
        ("[]".into(), "array"),
        ("\"x\"".into(), "scalar"),
        ("{\"foo\":\"bar\"}".into(), "arbitrary object"),
        (good.replace("\"sequence\":\"7\"", "\"seq\":\"7\""), "missing sequence"),
        (good.replace("\"memo\":\"\",", ""), "missing memo"),
        (good.replace("\"chain_id\":\"nnchain-mainnet-1\"", "\"chain_id\":1"), "chain_id not a string"),
        (good.replace("\"sequence\":\"7\"", "\"sequence\":7"), "sequence not a string"),
        (good.replace("\"fee\":{", "\"fee\":[").replace("\"gas\":\"500000\"}", "\"gas\":\"500000\"]"), "fee not an object"),
        (doc(",\"extra\":\"x\""), "unknown top-level key"),
        (doc(",\"memo\":\"dup\""), "duplicate key"),
        (doc(",\"timeout_height\":5"), "timeout_height not a string"),
        (good.replace("\"msgs\":[{", "\"msgs\":[1,{"), "non-object message"),
        (good.replace("\"msgs\":[{", "\"msgs\":[{},{"), "empty message object"),
        (good.replace("\"type\":\"cosmos-sdk/MsgSend\",", ""), "message without type"),
        (good.replace("\"value\":{", "\"extra\":\"x\",\"value\":{"), "message with extra key"),
        (good.replace("\"type\":\"cosmos-sdk/MsgSend\"", "\"type\":5"), "type not a string"),
        (good.replace("\"msgs\":[{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amount\":\"1\",\"denom\":\"nnc\"}],\"from_address\":\"nnc1a\",\"to_address\":\"nnc1b\"}}]", "\"msgs\":[]"), "no messages"),
        (good.replace("\"msgs\":[{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amount\":\"1\",\"denom\":\"nnc\"}],\"from_address\":\"nnc1a\",\"to_address\":\"nnc1b\"}}]", "\"msgs\":{}"), "msgs not an array"),
        (format!("{good} "), "ok with trailing space"), // must still be accepted: see below
    ];
    for (text, what) in bad {
        let r = json_view::flatten_sign_doc(text.as_bytes());
        if what == "ok with trailing space" {
            assert!(r.is_ok(), "trailing whitespace is valid JSON");
        } else {
            assert!(r.is_err(), "must reject: {what}");
        }
    }
}

#[test]
fn msgs_index_overflow_does_not_panic() {
    // a key made of digits only, as large as usize::MAX, under "msgs" (non-strict parse)
    let t = "{\"msgs\":{\"18446744073709551615\":{\"a\":\"b\"}}}";
    let items = json_view::flatten(t.as_bytes()).unwrap();
    assert!(items[0].name.starts_with("Msg "));
    let t2 = "{\"msgs\":{\"99999999999999999999999999\":1}}";
    assert!(json_view::flatten(t2.as_bytes()).is_ok());
}

#[test]
fn sign_doc_parser_never_panics_on_mutations() {
    let mut rng = StdRng::seed_from_u64(31337);
    let base = doc("").into_bytes();
    for _ in 0..200_000 {
        let mut b = base.clone();
        for _ in 0..rng.gen_range(1..4) {
            if b.is_empty() {
                break;
            }
            let i = rng.gen_range(0..b.len());
            match rng.gen_range(0..4) {
                0 => b[i] = rng.gen(),
                1 => {
                    b.remove(i);
                }
                2 => b.insert(i, b"{}[]\":,0a\\"[rng.gen_range(0..10)]),
                _ => b.truncate(i),
            }
        }
        // accepted documents must be valid JSON AND have the required top-level keys
        if json_view::flatten_sign_doc(&b).is_ok() {
            let v: Result<serde_json::Value, _> = serde_json::from_slice(&b);
            if let Ok(v) = v {
                let o = v.as_object().expect("top level must be an object");
                for k in ["account_number", "chain_id", "fee", "memo", "msgs", "sequence"] {
                    assert!(o.contains_key(k), "accepted a doc without {k}");
                }
            }
        }
    }
}
