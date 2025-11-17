use alloy::hex;
use alloy::primitives::{Address, Signature, address};
use eyre::Result;

fn main() -> Result<()> {
    let address = address!("0x664C7bA58aEE266307Cac0B5a8555095C1a4f7a0");
    let message =
        b"Ranked-choice voting is the single most important democracy reform needed in the US";
    let signature = hex!(
        "0x3ef5a537df46dc7113fd0d7bea4534315cac6238897b92dd52fd2fc2ff1bb9fb1b1e9f842836194b139f11e9c0d1edaf5fe32099690af3fc2b766b4f8d13cb111b"
    );

    verify_signature(&address, message, &signature)?;

    Ok(())
}

// Verifies a signed message from an address.
//
// See <https://alloy.rs/examples/wallets/verify_message/> for reference.
fn verify_signature(address: &Address, message: &[u8], signature: &[u8]) -> Result<()> {
    let recovered = Signature::from_raw(signature)?.recover_address_from_msg(message)?;

    eyre::ensure!(&recovered == address);

    Ok(())
}
