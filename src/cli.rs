use crate::circuit::{EASDemoCircuit, *};
use alloy::hex::FromHex;
use alloy::primitives::{Address, Bytes, Signature};
use anyhow::{Result, anyhow};
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{CircuitBuilder, WitnessFiller};
use clap::Args;

/// [`Params`] stores the constant parameters required during circuit setup.
#[derive(Args, Debug, Clone)]
struct CliParams {
    /// Maximum allowed length of the message (in bytes).
    #[arg(long, default_value = 256)]
    max_msg_len: usize,
    /// Maximum allowed length of the "GM" field (in bytes).
    #[arg(long, default_value = 16)]
    max_gm_len: usize,
}

/// [`Instance`] stores the high-level public inputs and outputs.
#[derive(Args, Debug, Clone)]
struct CliInstance {
    #[arg(long, default_value = "0xc48117F22c8095504aFCa9795DCCbdA2BF5FBc73")]
    attester_addr: String,
    #[arg(
        long,
        default_value = "Ranked choice voting is the single most important democracy reform needed in the US"
    )]
    msg: String,
    #[arg(long, default_value = "Binius")]
    gm_val: String,
    #[arg(long, default_value = "0x664C7bA58aEE266307Cac0B5a8555095C1a4f7a0")]
    signer: String,
    #[arg(
        long,
        default_value = "0x3ef5a537df46dc7113fd0d7bea4534315cac6238897b92dd52fd2fc2ff1bb9fb1b1e9f842836194b139f11e9c0d1edaf5fe32099690af3fc2b766b4f8d13cb111b"
    )]
    signature: String,
}

struct EASDemoExampleCircuit(EASDemoCircuit);

impl ExampleCircuit for EASDemoExampleCircuit {
    type Params = CliParams;
    type Instance = CliInstance;

    fn build(cli_params: CliParams, builder: &mut CircuitBuilder) -> Result<Self> {
        let params = circuit::Params {
            max_msg_len: cli_params.max_msg_len,
            max_gm_len: cli_params.max_gm_len,
        };
        let inner = EASDemoCircuit::build(params, builder).map_err(|err| anyhow!("{}", err))?;
        Ok(Self(inner))
    }

    fn populate_witness(
        &self,
        cli_instance: CliInstance,
        filler: &mut WitnessFiller,
    ) -> Result<()> {
        let sig = Bytes::from_hex(cli_instance.signature)?;
        let instance = circuit::Instance {
            attester_addr: Address::parse_checksummed(cli_instance.attester_addr, None)?,
            msg: cli_instance.msg,
            gm_val: cli_instance.gm_val,
            signer: Address::parse_checksummed(cli_instance.signer, None)?,
            signature: Signature::from_raw(sig.as_ref())?,
        };

        self.0
            .populate_witness(instance, filler)
            .map_err(|err| anyhow!("{}", err))
    }
}

fn main() -> Result<()> {
    Cli::<EASDemoExampleCircuit>::new("eas-demo")
        .about("Ethereum Attestation demo")
        .run()
}
