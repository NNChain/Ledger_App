use crate::json_view::Item;
use alloc::vec::Vec;
use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{Field, NbglGlyph, NbglReview};

/// Shows every field of the sign doc and returns true if the user approved.
pub fn ui_review_sign_doc(comm: &mut Comm, items: &[Item]) -> bool {
    const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/nnc_64x64.gif", NBGL));

    let fields: Vec<Field> = items
        .iter()
        .map(|it| Field {
            name: it.name.as_str(),
            value: it.value.as_str(),
        })
        .collect();

    NbglReview::new()
        .titles(
            "Review NNChain\ntransaction",
            "",
            "Sign transaction\non NNChain",
        )
        .glyph(&GLYPH)
        .show(comm, &fields)
}
