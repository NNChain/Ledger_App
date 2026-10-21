use crate::AppSW;
use ledger_device_sdk::io::{Command, CommandResponse};

/// Zondax-compatible version reply: [test_mode, major, minor, patch, device_locked].
pub fn handler_get_version(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let major: u8 = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0);
    let minor: u8 = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0);
    let patch: u8 = env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0);

    let mut response = command.into_response();
    response.append(&[0u8, major, minor, patch, 0u8])?;
    Ok(response)
}
