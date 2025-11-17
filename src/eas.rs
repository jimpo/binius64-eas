use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, FixedBytes, Signature};
use alloy::sol;
use eyre::Result;
use serde::{Deserialize, Deserializer};
use serde_repr::Deserialize_repr;

#[derive(Debug, PartialEq, Eq, Deserialize_repr)]
#[repr(u16)]
pub enum OffchainAttestationVersion {
    Legacy = 0,
    Version1 = 1,
    Version2 = 2,
}

sol! {
    #[derive(Debug, Deserialize)]
    struct AttestationV2 {
        uint16 version;
        bytes32 schema;
        address recipient;
        #[serde(deserialize_with = "deserialize_string_to_u64")]
        uint64 time;
        #[serde(deserialize_with = "deserialize_string_to_u64")]
        uint64 expirationTime;
        bool revocable;
        bytes data;
        bytes32 salt;
    }
}

fn deserialize_string_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
pub struct SignedOffchainAttestation {
    pub version: OffchainAttestationVersion,
    pub signature: Signature,
	#[serde(rename = "uid")]
    pub _uid: FixedBytes<32>,
    #[serde(flatten)]
    pub data: TypedData,
}

#[derive(Debug, Deserialize)]
pub struct AttestationInfo {
    #[serde(rename = "sig")]
    pub signed_attestation: SignedOffchainAttestation,
    pub signer: Address,
}

impl AttestationInfo {
    pub fn validate(&self) -> Result<()> {
        let Self {
            signed_attestation,
            signer,
        } = self;

        let signing_hash = signed_attestation.data.eip712_signing_hash()?;
        let recovered = signed_attestation
            .signature
            .recover_address_from_prehash(&signing_hash)?;

        eyre::ensure!(&recovered == signer);

        Ok(())
    }
}
