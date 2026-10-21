use crate::app_ui::address::ui_display_address;
use crate::utils::{address_string, compressed_pubkey, parse_path, NNC_HRP};
use crate::AppSW;
use ledger_device_sdk::io::{Command, CommandResponse};

/// GET_ADDR_SECP256K1: data = [hrp_len, hrp, path(5 x u32 LE)].
/// Replies with the 33 byte compressed public key followed by the `nnc` bech32 address.
pub fn handler_get_addr(command: Command<'_>, display: bool) -> Result<CommandResponse<'_>, AppSW> {
    let data = command.get_data();
    if data.is_empty() {
        return Err(AppSW::WrongLength);
    }
    let hrp_len = data[0] as usize;
    if !(3..=83).contains(&hrp_len) || data.len() != 1 + hrp_len + 20 {
        return Err(AppSW::WrongLength);
    }
    // Cosmos clients (e.g. cosmjs `publicKey`) ask with the HRP "cosmos" and only
    // use the public key from the reply. Whatever HRP is requested, this app
    // only ever produces and displays `nnc` addresses.
    let path = parse_path(&data[1 + hrp_len..])?;

    let pubkey = compressed_pubkey(&path)?;
    let address = address_string(NNC_HRP, &pubkey)?;

    let comm = command.into_comm();
    if display && !ui_display_address(comm, &address)? {
        return Err(AppSW::Deny);
    }

    let mut response = comm.begin_response();
    response.append(&pubkey)?;
    response.append(address.as_bytes())?;
    Ok(response)
}
