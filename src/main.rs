mod eas;
mod gm_schema;
mod circuit;
mod cli;

use crate::eas::{AttestationInfo, AttestationV2, OffchainAttestationVersion};
use crate::gm_schema::GmSchemaData;
use alloy::consensus::private::serde_json;
use alloy::hex;
use alloy::primitives::{Address, Signature, address};
use alloy::sol_types::SolType;
use eyre::{Result, ensure};

struct AttestedMessageInout<'a> {
    attester_address: Address,
    message: &'a [u8],
    expected_gm: &'a str,
}

struct AttestedMessageWitness<'a> {
    signer: Address,
    message_signature: &'a [u8],
    attestation_info: AttestationInfo,
}

fn naively_verify_attested_message(
    inout: AttestedMessageInout,
    witness: AttestedMessageWitness,
) -> Result<()> {
    let AttestedMessageInout {
        attester_address,
        message,
        expected_gm,
    } = inout;
    let AttestedMessageWitness {
        signer,
        message_signature,
        attestation_info,
    } = witness;

    const EAS_SCHEMA_ID: [u8; 32] =
        hex!("0x365f50a2e12159e29b002684b5c42a3c1ab67440b886b66ee9a4a9e8c8f7f528");

    // Verify that the anonymous signer signed the message.
    // See <https://alloy.rs/examples/wallets/verify_message/> for reference.
    let recovered = Signature::from_raw(message_signature)?.recover_address_from_msg(message)?;
    ensure!(recovered == signer);

    // Validate the attester's signature on the attestation
    attestation_info.validate()?;
    ensure!(attestation_info.signer == attester_address);
    println!("Attestation signature is valid");

    // Validate the signed attestation
    let signed_attestation = attestation_info.signed_attestation;
    ensure!(signed_attestation.version == OffchainAttestationVersion::Version2);

    let attestation = serde_json::from_value::<AttestationV2>(signed_attestation.data.message)?;
    ensure!(attestation.recipient == signer);
    ensure!(attestation.schema == EAS_SCHEMA_ID);
    ensure!(attestation.expirationTime == 0); // ensure never expires

    let gm_val = GmSchemaData::abi_decode(&attestation.data)?;
    ensure!(gm_val == expected_gm);

    Ok(())
}

fn main() -> Result<()> {
    let address = address!("0x664C7bA58aEE266307Cac0B5a8555095C1a4f7a0");
    let message =
        b"Ranked-choice voting is the single most important democracy reform needed in the US";
    let signature = hex!(
        "0x3ef5a537df46dc7113fd0d7bea4534315cac6238897b92dd52fd2fc2ff1bb9fb1b1e9f842836194b139f11e9c0d1edaf5fe32099690af3fc2b766b4f8d13cb111b"
    );

    // Attestation schema: <https://base.easscan.org/schema/view/0x365f50a2e12159e29b002684b5c42a3c1ab67440b886b66ee9a4a9e8c8f7f528>
    let attester_address = address!("0xc48117F22c8095504aFCa9795DCCbdA2BF5FBc73");
    let attestation_str = include_str!("../example-attest.json");
    let expected_gm = "Binius";

    // Attestation link: <https://base.easscan.org/offchain/url/#attestation=eNqlkktuHDEMRO%2FS64FBUvwuPR3PJYIsKDV5gCABcvxoxhcI4tJCC1HFepS%2BH%2FgGb3jcDmcZe4M%2FTPAPInwVJxhdYILF7MLqfEkBZonzFO1eClmUlbNlVXdoYeu16yJg%2BcuEBkYRtegAih4Dhyp00VU8LvFwaVuYa7vhpd7YXD1tHxQy7djkT5%2FFjmgPouUQIsD5ODMs5Nt5zuud7g953Jd9YhYwR%2B4uYw1noL0qdmNKnzG1J%2Bczc6NLrERzHzaLXFNnoMrLZKi0QFIhoWyGmHsy%2BkRfTDl25qnGDNNdp2pVJGeUL29roU98VT5tvovnxwfpnoGdueAu6bIhQk5Mbks4bmg6GJWDb7BvHrdfP3%2FX0wK%2BJIIvSpl0P6yGiY3%2FMTg2Dz1BYs4rrb2vsaLXlVWKC9aYcoV66dBmS5FlRKNkfyIP6GGJq3Lx8eMvWFGrgQ%3D%3D>
    let attestation_info = serde_json::from_str::<AttestationInfo>(attestation_str)?;

    let inout = AttestedMessageInout {
        attester_address,
        message,
        expected_gm,
    };
    let witness = AttestedMessageWitness {
        signer: address,
        message_signature: &signature,
        attestation_info,
    };

    naively_verify_attested_message(inout, witness)?;

    Ok(())
}
