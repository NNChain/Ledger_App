use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};

pub fn ui_menu_main(_: &mut Comm) -> NbglHomeAndSettings {
    const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/nnc_64x64.gif", NBGL));

    NbglHomeAndSettings::new().glyph(&GLYPH).infos(
        "NNChain",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS"),
    )
}
