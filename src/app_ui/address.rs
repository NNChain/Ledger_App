use crate::AppSW;
use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{NbglAddressReview, NbglGlyph};

pub fn ui_display_address(comm: &mut Comm, address: &str) -> Result<bool, AppSW> {
    const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/nnc_64x64.gif", NBGL));

    Ok(NbglAddressReview::new()
        .glyph(&GLYPH)
        .review_title("Verify NNChain address")
        .show(comm, address))
}
