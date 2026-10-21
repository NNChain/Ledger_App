//! Flattens an Amino JSON sign doc into (label, value) pairs for the review screens.
//!
//! The parser is strict: anything that is not well formed JSON is rejected, so
//! the device never signs bytes it could not display.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Which JSON key produced a leaf (only the two that form a coin line matter).
#[derive(Clone, Copy, PartialEq)]
enum Key {
    Amount,
    Denom,
    Other,
}

pub struct Item {
    pub name: String,
    pub value: String,
    key: Key,
    plen: u8,
    /// True for string and number leaves: only those may form a "<amount> <denom>" line.
    coin_ok: bool,
}

const MAX_DEPTH: usize = 16;
const MAX_ITEMS: usize = 80;
/// Total bytes of all labels and values shown on the review screens.
const MAX_DISPLAY_BYTES: usize = 3072;

/// What kind of JSON value a key holds (only the first byte of the value is inspected).
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Str,
    Obj,
    Arr,
    EmptyArr,
    Other,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    /// When set, the document must be an Amino `StdSignDoc`:
    /// `{account_number, chain_id, fee, memo, msgs[{type, value}], sequence[, timeout_height]}`.
    strict: bool,
    shape_ok: bool,
}

/// Checks the keys of one object against the required shape; `required` lists the
/// mandatory (key, kind) pairs and `optional` the allowed extra keys. No other key and
/// no duplicate is accepted.
fn shape_matches(keys: &[(String, Kind)], required: &[(&str, Kind)], optional: &[(&str, Kind)]) -> bool {
    for (i, (k, kind)) in keys.iter().enumerate() {
        if keys[..i].iter().any(|(p, _)| p == k) {
            return false;
        }
        let allowed = required.iter().chain(optional.iter()).find(|(name, _)| name == k);
        match allowed {
            Some((_, want)) => {
                if kind != want {
                    return false;
                }
            }
            None => return false,
        }
    }
    required.iter().all(|(name, _)| keys.iter().any(|(k, _)| k == name))
}

fn capitalize(s: String) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {
            let mut out = String::new();
            out.push(c.to_ascii_uppercase());
            out.push_str(chars.as_str());
            out
        }
        _ => s,
    }
}

fn friendly(path: &[String]) -> String {
    capitalize(friendly_raw(path))
}

fn friendly_raw(path: &[String]) -> String {
    if path.is_empty() {
        return String::from("Value");
    }
    if path[0] == "msgs" && path.len() >= 2 {
        let n: usize = path[1].parse().unwrap_or(0);
        let mut label = format!("Msg {}", n.saturating_add(1));
        let rest = &path[2..];
        let rest = if !rest.is_empty() && rest[0] == "value" {
            &rest[1..]
        } else {
            rest
        };
        for seg in rest {
            label.push(' ');
            label.push_str(seg);
        }
        return label;
    }
    if path.len() == 1 {
        match path[0].as_str() {
            "chain_id" => return String::from("Chain ID"),
            "account_number" => return String::from("Account number"),
            "sequence" => return String::from("Sequence"),
            "memo" => return String::from("Memo"),
            _ => {}
        }
    }
    let mut label = String::new();
    for (i, seg) in path.iter().enumerate() {
        if i > 0 {
            label.push(' ');
        }
        label.push_str(seg);
    }
    label
}

/// Everything outside printable ASCII is shown as `\u{XXXX}` so that look-alike
/// characters, bidirectional overrides and zero-width characters cannot disguise text.
fn escape_non_ascii(s: &str) -> String {
    if s.is_ascii() {
        return String::from(s);
    }
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            out.push_str(&format!("\\u{{{:X}}}", ch as u32));
        }
    }
    out
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\n' | b'\r' | b'\t') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn expect(&mut self, c: u8) -> Result<(), ()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    fn string(&mut self) -> Result<String, ()> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.s.get(self.i).ok_or(())?;
            self.i += 1;
            match c {
                b'"' => {
                    let text = String::from_utf8(out).map_err(|_| ())?;
                    return Ok(escape_non_ascii(&text));
                }
                b'\\' => {
                    let e = *self.s.get(self.i).ok_or(())?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        // A real backslash is shown doubled so it can never be confused
                        // with the literal escape text produced below ("\\n" = backslash + n).
                        b'\\' => out.extend_from_slice(b"\\\\"),
                        b'/' => out.push(b'/'),
                        // Control escapes are shown literally so they cannot hide text.
                        b'b' | b'f' | b'n' | b'r' | b't' => {
                            out.push(b'\\');
                            out.push(e);
                        }
                        b'u' => {
                            if self.i + 4 > self.s.len() {
                                return Err(());
                            }
                            let mut v: u32 = 0;
                            for k in 0..4 {
                                let h = self.s[self.i + k];
                                let d = match h {
                                    b'0'..=b'9' => h - b'0',
                                    b'a'..=b'f' => h - b'a' + 10,
                                    b'A'..=b'F' => h - b'A' + 10,
                                    _ => return Err(()),
                                };
                                v = (v << 4) | d as u32;
                            }
                            self.i += 4;
                            match char::from_u32(v) {
                                // Printable character: re-encoded here, any non-ASCII
                                // character is escaped for display at the end.
                                Some('\\') => out.extend_from_slice(b"\\\\"),
                                Some(ch) if v >= 0x20 && v != 0x7f => {
                                    let mut buf = [0u8; 4];
                                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                                }
                                // Control characters and lone surrogates are shown literally.
                                _ => out.extend_from_slice(format!("\\u{:04X}", v).as_bytes()),
                            }
                        }
                        _ => return Err(()),
                    }
                }
                0x00..=0x1f | 0x7f => return Err(()),
                _ => out.push(c),
            }
        }
    }

    fn leaf(path: &[String], out: &mut Vec<Item>, value: String, coin_ok: bool) -> Result<(), ()> {
        if out.len() >= MAX_ITEMS {
            return Err(());
        }
        let name = friendly(path);
        let used: usize = out.iter().map(|i| i.name.len() + i.value.len()).sum();
        if used + name.len() + value.len() > MAX_DISPLAY_BYTES {
            return Err(());
        }
        let key = match path.last().map(|s| s.as_str()) {
            Some("amount") => Key::Amount,
            Some("denom") => Key::Denom,
            _ => Key::Other,
        };
        out.push(Item {
            name,
            value,
            key,
            plen: path.len() as u8,
            coin_ok,
        });
        Ok(())
    }

    fn peek_kind(&self) -> Kind {
        match self.peek() {
            Some(b'"') => Kind::Str,
            Some(b'{') => Kind::Obj,
            Some(b'[') => {
                let mut k = self.i + 1;
                while k < self.s.len() && matches!(self.s[k], b' ' | b'\n' | b'\r' | b'\t') {
                    k += 1;
                }
                if self.s.get(k) == Some(&b']') {
                    Kind::EmptyArr
                } else {
                    Kind::Arr
                }
            }
            _ => Kind::Other,
        }
    }

    /// Strict JSON number: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
    fn number(&mut self) -> Result<(), ()> {
        let digits = |p: &mut Self| -> usize {
            let st = p.i;
            while p.i < p.s.len() && p.s[p.i].is_ascii_digit() {
                p.i += 1;
            }
            p.i - st
        };
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err(()),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if digits(self) == 0 {
                return Err(());
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                return Err(());
            }
        }
        Ok(())
    }

    fn literal(&mut self, lit: &[u8]) -> Result<(), ()> {
        if self.s.len() >= self.i + lit.len() && &self.s[self.i..self.i + lit.len()] == lit {
            self.i += lit.len();
            Ok(())
        } else {
            Err(())
        }
    }

    /// A coin object ({"amount": "..", "denom": ".."}) inside a list becomes one
    /// line: "<label>: 1000 nnc".
    fn merge_coin(path: &[String], out: &mut Vec<Item>, start: usize) {
        let is_list_entry = path
            .last()
            .map(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .unwrap_or(false);
        if !is_list_entry || out.len() != start + 2 {
            return;
        }
        let want = (path.len() + 1) as u8;
        let ok = out[start].key == Key::Amount
            && out[start + 1].key == Key::Denom
            && out[start].plen == want
            && out[start + 1].plen == want
            && out[start].coin_ok
            && out[start + 1].coin_ok;
        if !ok {
            return;
        }
        let (Some(denom), Some(amount)) = (out.pop(), out.pop()) else {
            return;
        };
        // "Fee amount 0" -> "Fee amount"; later coins keep their index.
        let label_path: &[String] = if path.last().map(|s| s.as_str()) == Some("0") {
            &path[..path.len() - 1]
        } else {
            path
        };
        out.push(Item {
            name: friendly(label_path),
            value: format!("{} {}", amount.value, denom.value),
            key: Key::Other,
            plen: path.len() as u8,
            coin_ok: false,
        });
    }

    fn value(
        &mut self,
        path: &mut Vec<String>,
        out: &mut Vec<Item>,
        depth: usize,
    ) -> Result<(), ()> {
        if depth > MAX_DEPTH {
            return Err(());
        }
        self.ws();
        match self.peek().ok_or(())? {
            b'{' => {
                self.i += 1;
                self.ws();
                // Objects whose shape is checked: the top level and every entry of `msgs`.
                let track = self.strict
                    && (path.is_empty() || (path.len() == 2 && path[0] == "msgs"));
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    if track {
                        // an empty document or an empty message has none of the required keys
                        self.shape_ok = false;
                    }
                    return Self::leaf(path, out, String::from("{}"), false);
                }
                let start = out.len();
                let mut seen: Vec<(String, Kind)> = Vec::new();
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    self.expect(b':')?;
                    if track {
                        self.ws();
                        let kind = self.peek_kind();
                        seen.push((k.clone(), kind));
                    }
                    path.push(k);
                    self.value(path, out, depth + 1)?;
                    path.pop();
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            break;
                        }
                        _ => return Err(()),
                    }
                }
                Self::merge_coin(path, out, start);
                if track {
                    let ok = if path.is_empty() {
                        shape_matches(
                            &seen,
                            &[
                                ("account_number", Kind::Str),
                                ("chain_id", Kind::Str),
                                ("fee", Kind::Obj),
                                ("memo", Kind::Str),
                                ("msgs", Kind::Arr),
                                ("sequence", Kind::Str),
                            ],
                            &[("timeout_height", Kind::Str)],
                        )
                    } else {
                        shape_matches(&seen, &[("type", Kind::Str), ("value", Kind::Obj)], &[])
                    };
                    if !ok {
                        self.shape_ok = false;
                    }
                }
                Ok(())
            }
            b'[' => {
                self.i += 1;
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Self::leaf(path, out, String::from("[]"), false);
                }
                let mut idx = 0usize;
                let msgs_list = self.strict && path.len() == 1 && path[0] == "msgs";
                loop {
                    if msgs_list {
                        self.ws();
                        if self.peek() != Some(b'{') {
                            self.shape_ok = false;
                        }
                    }
                    path.push(format!("{}", idx));
                    self.value(path, out, depth + 1)?;
                    path.pop();
                    idx += 1;
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        _ => return Err(()),
                    }
                }
                Ok(())
            }
            b'"' => {
                let s = self.string()?;
                Self::leaf(path, out, s, true)
            }
            b't' => {
                self.literal(b"true")?;
                Self::leaf(path, out, String::from("true"), false)
            }
            b'f' => {
                self.literal(b"false")?;
                Self::leaf(path, out, String::from("false"), false)
            }
            b'n' => {
                self.literal(b"null")?;
                Self::leaf(path, out, String::from("null"), false)
            }
            b'-' | b'0'..=b'9' => {
                let start = self.i;
                self.number()?;
                let n = core::str::from_utf8(&self.s[start..self.i]).map_err(|_| ())?;
                Self::leaf(path, out, String::from(n), true)
            }
            _ => Err(()),
        }
    }
}

fn run(input: &[u8], strict: bool) -> Result<Vec<Item>, ()> {
    let mut p = Parser {
        s: input,
        i: 0,
        strict,
        shape_ok: true,
    };
    let mut out = Vec::new();
    let mut path = Vec::new();
    if strict {
        p.ws();
        if p.peek() != Some(b'{') {
            return Err(());
        }
    }
    p.value(&mut path, &mut out, 0)?;
    p.ws();
    if p.i != input.len() || out.is_empty() || !p.shape_ok {
        return Err(());
    }
    Ok(out)
}

/// Parses any JSON document and returns its leaf values with readable labels.
/// (Used by the host-side differential tests; the app signs through `flatten_sign_doc`.)
#[allow(dead_code)]
pub fn flatten(input: &[u8]) -> Result<Vec<Item>, ()> {
    run(input, false)
}

/// Like `flatten`, and additionally requires the structure of an Amino `StdSignDoc`:
/// top-level keys exactly `account_number, chain_id, fee, memo, msgs, sequence`
/// (+ optional `timeout_height`) with the right value kinds, and every entry of `msgs`
/// an object with exactly `type` (string) and `value` (object). Anything else is refused,
/// so the device never signs arbitrary attacker-chosen JSON.
pub fn flatten_sign_doc(input: &[u8]) -> Result<Vec<Item>, ()> {
    run(input, true)
}
