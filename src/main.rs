//! NNChain Ledger app.
//!
//! Speaks the same APDU protocol as the Cosmos Ledger app (CLA 0x55) so that
//! existing Cosmos clients (cosmjs, ledger-cosmos-js) work unchanged, but is
//! restricted to the `nnc` address prefix and the m/44'/118' key path.

#![no_std]
#![no_main]

extern crate alloc;

mod bech32;
mod der;
mod json_view;
mod utils;
mod app_ui {
    pub mod address;
    pub mod menu;
    pub mod sign;
}
mod handlers {
    pub mod get_addr;
    pub mod get_version;
    pub mod sign;
}

use app_ui::menu::ui_menu_main;
use handlers::{
    get_addr::handler_get_addr,
    get_version::handler_get_version,
    sign::{handler_sign, SignStage, TxContext},
};
use ledger_device_sdk::io::{self, init_comm, ApduHeader, Comm, Command, Reply};
use ledger_device_sdk::nbgl::{NbglReviewStatus, StatusType};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

ledger_device_sdk::define_comm!(COMM);

const CLA: u8 = 0x55;
const INS_GET_VERSION: u8 = 0x00;
const INS_SIGN_SECP256K1: u8 = 0x02;
const INS_GET_ADDR_SECP256K1: u8 = 0x04;

const P1_SIGN_INIT: u8 = 0x00;
const P1_SIGN_ADD: u8 = 0x01;
const P1_SIGN_LAST: u8 = 0x02;
const P2_JSON: u8 = 0x00;

/// Application status words (Zondax Cosmos app compatible where it matters).
#[repr(u16)]
#[derive(Clone, Copy, PartialEq)]
pub enum AppSW {
    Deny = 0x6986,
    DataInvalid = 0x6984,
    WrongLength = 0x6700,
    WrongP1P2 = 0x6B00,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    CommError = 0x6F00,
    InvalidPath = 0x6A81,
    InvalidHrp = 0x6A82,
    TxTooLarge = 0x6A83,
    KeyDeriveFail = 0xB009,
    HashFail = 0xB006,
    TxSignFail = 0xB008,
    Ok = 0x9000,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Reply {
        Reply(sw as u16)
    }
}

impl From<io::CommError> for AppSW {
    fn from(_e: io::CommError) -> Self {
        AppSW::CommError
    }
}

#[derive(Debug)]
pub enum Instruction {
    GetVersion,
    GetAddr { display: bool },
    Sign { stage: u8 },
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    fn try_from(h: ApduHeader) -> Result<Self, Self::Error> {
        match (h.ins, h.p1, h.p2) {
            (INS_GET_VERSION, 0, 0) => Ok(Instruction::GetVersion),
            (INS_GET_ADDR_SECP256K1, 0 | 1, 0) => Ok(Instruction::GetAddr { display: h.p1 == 1 }),
            (INS_SIGN_SECP256K1, P1_SIGN_INIT | P1_SIGN_ADD | P1_SIGN_LAST, P2_JSON) => {
                Ok(Instruction::Sign { stage: h.p1 })
            }
            (INS_GET_VERSION | INS_GET_ADDR_SECP256K1 | INS_SIGN_SECP256K1, _, _) => {
                Err(AppSW::WrongP1P2)
            }
            _ => Err(AppSW::InsNotSupported),
        }
    }
}

fn show_status_and_home_if_needed(
    comm: &mut Comm,
    ins: &Instruction,
    tx_ctx: &mut TxContext,
    status: &AppSW,
) {
    let (show_status, status_type) = match (ins, status) {
        (Instruction::GetAddr { display: true }, AppSW::Deny | AppSW::Ok) => {
            (true, StatusType::Address)
        }
        (Instruction::Sign { stage }, AppSW::Deny | AppSW::Ok)
            if *stage == P1_SIGN_LAST && tx_ctx.finished() =>
        {
            (true, StatusType::Transaction)
        }
        (_, _) => (false, StatusType::Transaction),
    };

    if show_status {
        let success = *status == AppSW::Ok;
        NbglReviewStatus::new()
            .status_type(status_type)
            .show(comm, success);
        tx_ctx.home.show_and_return();
    }
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    let comm = init_comm(&COMM);
    comm.set_expected_cla(CLA);

    let mut tx_ctx = TxContext::new();
    tx_ctx.home = ui_menu_main(comm);
    tx_ctx.home.show_and_return();

    loop {
        let command = comm.next_command();
        let decoded = command.decode::<Instruction>();
        let Ok(ins) = decoded else {
            let _ = comm.send(&[], decoded.unwrap_err());
            continue;
        };

        let status = match handle_apdu(command, &ins, &mut tx_ctx) {
            Ok(reply) => {
                let _ = reply.send(AppSW::Ok);
                AppSW::Ok
            }
            Err(sw) => {
                let _ = comm.send(&[], sw);
                sw
            }
        };
        show_status_and_home_if_needed(comm, &ins, &mut tx_ctx, &status);
    }
}

fn handle_apdu<'a>(
    command: Command<'a>,
    ins: &Instruction,
    ctx: &mut TxContext,
) -> Result<io::CommandResponse<'a>, AppSW> {
    match ins {
        // Any other command ends a signing session in progress (multi-chunk rule: a new INS
        // clears in-progress state), so chunks can never be completed across other commands.
        Instruction::GetVersion => {
            ctx.abort_session();
            handler_get_version(command)
        }
        Instruction::GetAddr { display } => {
            ctx.abort_session();
            handler_get_addr(command, *display)
        }
        Instruction::Sign { stage } => {
            let stage = match *stage {
                P1_SIGN_INIT => SignStage::Init,
                P1_SIGN_ADD => SignStage::Add,
                _ => SignStage::Last,
            };
            handler_sign(command, stage, ctx)
        }
    }
}
