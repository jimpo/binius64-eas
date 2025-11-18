use alloy::primitives::utils::{EIP191_PREFIX, eip191_message};
use alloy::primitives::{Address, Signature, keccak256};
use binius_circuits::bignum::BigUint;
use binius_circuits::ecdsa::ecrecover;
use binius_circuits::fixed_byte_vec::ByteVec;
use binius_circuits::keccak::Keccak256;
use binius_circuits::keccak::fixed_length::keccak256 as keccak256_gadget;
use binius_core::Word;
use binius_core::consts::{WORD_SIZE_BITS, WORD_SIZE_BYTES};
use binius_frontend::util::{byteswap, pack_bytes_into_wires_le};
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use eyre::{Result, ensure};
use std::iter::repeat_with;
use std::{array, iter};

/// Number of 64-bit words required to specify a 160-bit address.
const N_ADDRESS_WORDS: usize = 160usize.div_ceil(WORD_SIZE_BITS);

/// [`Params`] stores the constant parameters required during circuit setup.
pub struct Params {
    /// Maximum allowed length of the message (in bytes).
    pub max_msg_len: usize,
    /// Maximum allowed length of the "GM" field (in bytes).
    pub max_gm_len: usize,
}

/// [`Instance`] stores the high-level public inputs and outputs.
pub struct Instance {
    pub attester_addr: Address,
    pub msg: String,
    pub gm_val: String,
    pub signer: Address,
    pub signature: Signature,
}

/// The circuit structure stores information about the circuit wires, required for witness
/// population.
pub struct EASDemoCircuit {
    params: Params,
    attester_addr: [Wire; N_ADDRESS_WORDS],
    msg: Vec<Wire>,
    gm_val: Vec<Wire>,
    msg_len: Wire,
    gm_len: Wire,
    sig_r: BigUint,
    sig_s: BigUint,
    sig_recid_odd: Wire,
    signer: [Wire; N_ADDRESS_WORDS],
    check_message_signature_output: CheckMessageSignatureOutput,
}

impl EASDemoCircuit {
    pub fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
        ensure!(params.max_msg_len.is_multiple_of(WORD_SIZE_BYTES));
        ensure!(params.max_gm_len.is_multiple_of(WORD_SIZE_BYTES));

        let max_msg_len_words = params.max_msg_len / WORD_SIZE_BYTES;
        let max_gm_len_words = params.max_gm_len / WORD_SIZE_BYTES;

        // Declare the input/output wires.
        let attester_addr: [_; N_ADDRESS_WORDS] = array::from_fn(|_| builder.add_inout());
        let msg = repeat_with(|| builder.add_inout())
            .take(max_msg_len_words)
            .collect::<Vec<_>>();
        let gm_val = repeat_with(|| builder.add_inout())
            .take(max_gm_len_words)
            .collect::<Vec<_>>();

        // Actual lengths of the message and "GM" message
        let msg_len = builder.add_inout();
        let gm_len = builder.add_inout();

        // Create the non-deterministic witness wires.
        let sig_r = BigUint::new_witness(builder, 256 / WORD_SIZE_BITS);
        let sig_s = BigUint::new_witness(builder, 256 / WORD_SIZE_BITS);
        let sig_recid_odd = builder.add_witness();

        let signer: [_; N_ADDRESS_WORDS] = array::from_fn(|_| builder.add_witness());

		// Check that the signature on the message is valid.
        let check_message_signature_output = check_message_signature(
            &mut builder.subcircuit("check message sig"),
            signer,
            &msg,
            msg_len,
            &sig_r,
            &sig_s,
            sig_recid_odd,
        );

		// TODO: Check that the attester's signature on the attestation is valid
		// TODO: Check the contents of the attestation

        Ok(Self {
            params,
            attester_addr,
            msg,
            gm_val,
            msg_len,
            gm_len,
            sig_r,
            sig_s,
            sig_recid_odd,
            signer,
            check_message_signature_output,
        })
    }

    pub fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
        let Self {
            params,
            attester_addr,
            msg,
            gm_val,
            msg_len,
            gm_len,
            sig_r,
            sig_s,
            sig_recid_odd,
            signer,
            check_message_signature_output,
        } = self;

        let msg_bytes = instance.msg.as_bytes();
        let gm_val_bytes = instance.gm_val.as_bytes();

        ensure!(msg_bytes.len() <= params.max_msg_len);
        ensure!(gm_val_bytes.len() <= params.max_gm_len);

        pack_bytes_into_wires_le(w, attester_addr, instance.attester_addr.as_slice());
        pack_bytes_into_wires_le(w, msg, msg_bytes);
        pack_bytes_into_wires_le(w, gm_val, gm_val_bytes);

        w[*msg_len] = Word(msg_bytes.len() as u64);
        w[*gm_len] = Word(gm_val_bytes.len() as u64);

        sig_r.populate_limbs(w, instance.signature.r().as_limbs());
        sig_s.populate_limbs(w, instance.signature.s().as_limbs());
        w[*sig_recid_odd] = Word(if instance.signature.v() { u64::MAX } else { 0 });

        pack_bytes_into_wires_le(w, signer, instance.signer.as_slice());

        let padded_message = eip191_message(msg_bytes);
        check_message_signature_output
            .msg_keccak
            .populate_message(w, &padded_message);

        // TODO: This should get handled by populate_message
        let msg_digest = keccak256(padded_message);
        check_message_signature_output
            .msg_keccak
            .populate_digest(w, msg_digest.0);

        Ok(())
    }
}

struct CheckMessageSignatureOutput {
    msg_keccak: Keccak256,
}

/// Builds a subcircuit that checks a signature on the message and returns the signer.
///
/// This code is heavily based on the [ethsign] example in the binius64 repo.
///
/// ## Returns
///
/// Wires containing the recovered address of the signer.
///
/// [ethsign]: <https://github.com/binius-zk/binius64/blob/main/prover/examples/src/circuits/ethsign.rs>
fn check_message_signature(
    builder: &mut CircuitBuilder,
    signer: [Wire; N_ADDRESS_WORDS],
    msg: &[Wire],
    msg_len: Wire,
    r: &BigUint,
    s: &BigUint,
    recid_odd: Wire,
) -> CheckMessageSignatureOutput {
    // Calculate EIP-191 padded message length
    let msg_keccak = eip191_hash_gadget(builder, msg, msg_len);

    // The Keccak digest is little endian encoded into 4 words, while Ethereum expects
    // big endian
    let z = BigUint {
        limbs: msg_keccak
            .digest
            .iter()
            .rev()
            .map(|&word| byteswap(builder, word))
            .collect(),
    };

    let public_key = ecrecover(builder, &z, r, s, recid_odd);

    // Check that public key is not a point-at-infinity
    builder.assert_false("recovered_pk_not_pai", public_key.is_point_at_infinity);

    // Concatenate x & y in _big_ endian, hash the result to obtain the address
    let public_key_serialized = Iterator::chain(
        public_key.x.limbs.iter().rev(),
        public_key.y.limbs.iter().rev(),
    )
    .map(|&word| byteswap(builder, word))
    .collect::<Vec<_>>();

    // Compute address as Keccak-256 of the serialized public key
    let address_digest = keccak256_gadget(builder, &public_key_serialized, 64);
    assert_address_eq(builder, &address_digest, &signer);

    CheckMessageSignatureOutput { msg_keccak }
}

/// Helper function to compute EIP-191 hash of a message using Keccak256
fn eip191_hash_gadget(builder: &mut CircuitBuilder, msg: &[Wire], msg_len: Wire) -> Keccak256 {
    let max_msg_len = msg.len() * WORD_SIZE_BYTES;
    let eip191_max_len = EIP191_PREFIX.len() + format!("{max_msg_len}").len() + max_msg_len;

    let zero = builder.add_constant(Word::ZERO);

    let eip191_padded_msg = repeat_with(|| builder.add_witness())
        .take(eip191_max_len)
        .collect::<Vec<_>>();

    let eip191_prefix_len = builder.add_constant(Word(EIP191_PREFIX.len() as u64));
    // TODO: This is hard-coded for the current value. Fix with multiplexer.
    let eip191_len_len = builder.add_constant(Word(2));

    let (eip191_padded_msg_len, cout) =
        builder.iadd_cin_cout(eip191_prefix_len, eip191_len_len, zero);
    builder.assert_false("no overflow", cout);

    // TODO: Check that the data inside the EIP-191 message is correct with slicing.

    let (eip191_padded_msg_len, cout) = builder.iadd_cin_cout(eip191_padded_msg_len, msg_len, zero);
    builder.assert_false("no overflow", cout);

    // Compute the Keccak-256 hash of the message
    let msg_digest = array::from_fn(|_| builder.add_witness());
    Keccak256::new(
        builder,
        eip191_padded_msg_len,
        msg_digest,
        eip191_padded_msg.to_vec(),
    )
}

fn assert_address_eq(b: &CircuitBuilder, digest: &[Wire], address: &[Wire]) {
    assert_eq!(digest.len(), 4);
    assert_eq!(address.len(), 3);

    let digest_len = b.add_constant_64(32);
    let digest_byte_vec = ByteVec::new(digest.to_vec(), digest_len);
    let digest_sliced = digest_byte_vec.slice_const_range(b, 12..32);

    for (i, (&lhs_i, rhs_i)) in iter::zip(address, digest_sliced.data).enumerate() {
        b.assert_eq(format!("address_word_{i}"), lhs_i, rhs_i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex;
    use alloy::primitives::address;
    use binius_core::verify::verify_constraints;
	use eyre::eyre;

    #[test]
    fn test_correct_inputs() -> Result<()> {
        let params = Params {
            max_msg_len: 256,
            max_gm_len: 16,
        };

        // Set up the circuit
        let mut builder = CircuitBuilder::new();
        let eas_demo = EASDemoCircuit::build(params, &mut builder)?;
        let circuit = builder.build();

        // Create the high-level instance
        let signature = Signature::from_raw(&hex!(
            "0x3ef5a537df46dc7113fd0d7bea4534315cac6238897b92dd52fd2fc2ff1bb9fb1b1e9f842836194b139f11e9c0d1edaf5fe32099690af3fc2b766b4f8d13cb111b"
        ))?;
        let instance = Instance {
			attester_addr: address!("0xc48117F22c8095504aFCa9795DCCbdA2BF5FBc73"),
			msg:
			"Ranked-choice voting is the single most important democracy reform needed in the US".to_string(),
			gm_val: "Binius".to_string(),
			signature,
			signer: address!("0x664C7bA58aEE266307Cac0B5a8555095C1a4f7a0"),
		};

        // Populate the witness using the high-level instance data
        let mut witness = circuit.new_witness_filler();
        eas_demo.populate_witness(instance, &mut witness)?;

        // Compute the automatically-populated internal wire values.
        circuit.populate_wire_witness(&mut witness)?;

        // Naively verify the constraints
        let cs = circuit.constraint_system();
        let witness_vec = witness.into_value_vec();
        verify_constraints(cs, &witness_vec).map_err(|err| eyre!("{:?}", err))?;

        Ok(())
    }

	#[test]
	#[ignore]
	fn test_correct_inputs_full_prove_verify() -> Result<()> {
		use binius_prover::hash::parallel_compression::ParallelCompressionAdaptor;
		use binius_prover::{OptimalPackedB128, Prover};
		use binius_verifier::config::StdChallenger;
		use binius_verifier::hash::{StdCompression, StdDigest};
		use binius_verifier::transcript::{ProverTranscript, VerifierTranscript};
		use binius_verifier::Verifier;

		let params = Params {
			max_msg_len: 256,
			max_gm_len: 16,
		};

		// Set up the circuit
		let mut builder = CircuitBuilder::new();
		let eas_demo = EASDemoCircuit::build(params, &mut builder)?;
		let circuit = builder.build();

		// Create the high-level instance
		let signature = Signature::from_raw(&hex!(
            "0x3ef5a537df46dc7113fd0d7bea4534315cac6238897b92dd52fd2fc2ff1bb9fb1b1e9f842836194b139f11e9c0d1edaf5fe32099690af3fc2b766b4f8d13cb111b"
        ))?;
		let instance = Instance {
			attester_addr: address!("0xc48117F22c8095504aFCa9795DCCbdA2BF5FBc73"),
			msg:
			"Ranked-choice voting is the single most important democracy reform needed in the US".to_string(),
			gm_val: "Binius".to_string(),
			signature,
			signer: address!("0x664C7bA58aEE266307Cac0B5a8555095C1a4f7a0"),
		};

		// Populate the witness using the high-level instance data
		let mut witness = circuit.new_witness_filler();
		eas_demo.populate_witness(instance, &mut witness)?;

		// Compute the automatically-populated internal wire values.
		circuit.populate_wire_witness(&mut witness)?;

		// Naively verify the constraints
		let cs = circuit.constraint_system();
		let witness_vec = witness.into_value_vec();
		verify_constraints(cs, &witness_vec).map_err(|err| eyre!("{:?}", err))?;

		// Prove/verify the circuit
		let compression = ParallelCompressionAdaptor::new(StdCompression::default());
		let verifier = Verifier::<StdDigest, _>::setup(cs.clone(), 1, StdCompression::default())?;
		let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(verifier.clone(), compression)?;

		let challenger = StdChallenger::default();
		let mut prover_transcript = ProverTranscript::new(challenger.clone());
		let public_words = witness_vec.public().to_vec();
		prover.prove(witness_vec, &mut prover_transcript)?;
		let proof = prover_transcript.finalize();

		let mut verifier_transcript = VerifierTranscript::new(challenger, proof);
		verifier.verify(&public_words, &mut verifier_transcript)?;
		verifier_transcript.finalize()?;

		println!("✓ proof successfully verified");

		Ok(())
	}
}
