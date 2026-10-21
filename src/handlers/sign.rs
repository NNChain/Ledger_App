use crate::app_ui::sign::ui_review_sign_doc;
use crate::json_view::flatten_sign_doc;
use crate::utils::{der_low_s, parse_path, sha256, Path, NNC_HRP, PATH_BYTES};
use crate::AppSW;
use alloc::vec::Vec;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};
use ledger_device_sdk::io::{Command, CommandResponse};
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

/// Largest sign doc (bytes) accepted by the app. Bounded by the device heap.
const MAX_SIGN_DOC_LEN: usize = 3072;

#[derive(Clone, Copy, PartialEq)]
pub enum SignStage {
    Init,
    Add,
    Last,
}

pub struct TxContext {
    buf: Vec<u8>,
    path: Path,
    started: bool,
    finished: bool,
    pub home: NbglHomeAndSettings,
}

impl TxContext {
    pub fn new() -> Self {
        TxContext {
            buf: Vec::new(),
            path: [0; 5],
            started: false,
            finished: false,
            home: Default::default(),
        }
    }

    pub fn finished(&self) -> bool {
        self.finished
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.path = [0; 5];
        self.started = false;
        self.finished = false;
    }

    /// Ends a session that is still in progress (another command arrived).
    pub fn abort_session(&mut self) {
        self.end_session();
    }

    /// Drops the sign doc and the key path once a signing session is over, so a
    /// later ADD/LAST chunk can never be appended to (or signed with) stale state.
    /// `finished` is kept: the main loop uses it to show the status screen.
    fn end_session(&mut self) {
        self.buf.clear();
        self.path = [0; 5];
        self.started = false;
    }
}

/// SIGN_SECP256K1 in JSON (Amino) mode.
/// INIT: path(20, LE) [+ hrp_len + hrp]. ADD/LAST: raw sign doc bytes.
/// The assembled document must be a well-formed Amino `StdSignDoc` (see `json_view`).
pub fn handler_sign<'a>(
    command: Command<'a>,
    stage: SignStage,
    ctx: &mut TxContext,
) -> Result<CommandResponse<'a>, AppSW> {
    let data = command.get_data();

    match stage {
        SignStage::Init => {
            ctx.reset();
            if data.len() < PATH_BYTES {
                return Err(AppSW::WrongLength);
            }
            ctx.path = parse_path(&data[..PATH_BYTES])?;
            let extra = &data[PATH_BYTES..];
            if !extra.is_empty() {
                let hrp_len = extra[0] as usize;
                if extra.len() != 1 + hrp_len || &extra[1..] != NNC_HRP.as_bytes() {
                    return Err(AppSW::InvalidHrp);
                }
            }
            ctx.started = true;
            Ok(command.into_response())
        }
        SignStage::Add | SignStage::Last => {
            if !ctx.started {
                return Err(AppSW::DataInvalid);
            }
            if ctx.buf.len() + data.len() > MAX_SIGN_DOC_LEN {
                ctx.reset();
                return Err(AppSW::TxTooLarge);
            }
            ctx.buf.extend_from_slice(data);

            if stage == SignStage::Add {
                return Ok(command.into_response());
            }

            // Last chunk: parse strictly, show everything, then sign.
            let items = match flatten_sign_doc(&ctx.buf) {
                Ok(v) => v,
                Err(_) => {
                    ctx.reset();
                    return Err(AppSW::DataInvalid);
                }
            };

            let comm = command.into_comm();
            let approved = ui_review_sign_doc(comm, &items);
            ctx.finished = true;
            if !approved {
                ctx.end_session();
                return Err(AppSW::Deny);
            }

            let result = sign_digest(&ctx.buf, &ctx.path);
            ctx.end_session();
            let (der, len) = result?;

            let mut response = comm.begin_response();
            response.append(&der[..len])?;
            Ok(response)
        }
    }
}

/// SHA-256 of the exact bytes that were reviewed, signed with RFC6979 ECDSA and
/// normalised to low-S DER.
fn sign_digest(doc: &[u8], path: &Path) -> Result<([u8; 72], usize), AppSW> {
    let digest = sha256(doc)?;
    let (sig, siglen, _parity) = Secp256k1::derive_from_path(path)
        .deterministic_sign(&digest)
        .map_err(|_| AppSW::TxSignFail)?;
    der_low_s(&sig[..siglen as usize])
}
