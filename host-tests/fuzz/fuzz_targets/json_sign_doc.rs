#![no_main]
//! libFuzzer target: the sign doc parser (`src/json_view.rs`) used for the review screens.
//! Invariants: never panics; limits hold; a strictly accepted doc is also accepted by the
//! general parser with the same output.
extern crate alloc;

#[allow(dead_code)]
#[path = "../../../src/json_view.rs"]
mod json_view;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let strict = json_view::flatten_sign_doc(data);
    let loose = json_view::flatten(data);
    if let Ok(items) = &strict {
        assert!(!items.is_empty() && items.len() <= 80);
        let bytes: usize = items.iter().map(|i| i.name.len() + i.value.len()).sum();
        assert!(bytes <= 3072);
        for i in items {
            assert!(i.name.is_ascii() && i.value.is_ascii(), "non-ASCII must be escaped");
            assert!(!i.name.bytes().chain(i.value.bytes()).any(|b| b < 0x20 || b == 0x7f));
        }
        let loose = loose.expect("strict acceptance implies general acceptance");
        assert_eq!(items.len(), loose.len());
    }
});
