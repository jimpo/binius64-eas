use alloy::primitives::Address;
use binius_core::Word;
use binius_core::consts::WORD_SIZE_BYTES;
use binius_frontend::util::pack_bytes_into_wires_le;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use eyre::{Result, ensure};
use std::array;
use std::iter::repeat_with;

/// Number of 64-bit words required to specify a 160-bit address.
const N_ADDRESS_WORDS: usize = 160usize.div_ceil(64);

/// [`Params`] stores the constant parameters required during circuit setup.
struct Params {
    /// Maximum allowed length of the message (in bytes).
    max_msg_len: usize,
    /// Maximum allowed length of the "GM" field (in bytes).
    max_gm_len: usize,
}

/// [`Instance`] stores the high-level public inputs and outputs.
struct Instance {
    attester_addr: Address,
    msg: String,
    gm_val: String,
}

/// The circuit structure stores information about the circuit wires, required for witness
/// population.
struct EASDemoCircuit {
    params: Params,
    attester_addr: [Wire; N_ADDRESS_WORDS],
    msg: Vec<Wire>,
    gm_val: Vec<Wire>,
    msg_len: Wire,
    gm_len: Wire,
}

impl EASDemoCircuit {
    fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
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

        Ok(Self {
            params,
            attester_addr,
            msg,
            gm_val,
            msg_len,
            gm_len,
        })
    }

    fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
        let Self {
            params,
            attester_addr,
            msg,
            gm_val,
            msg_len,
            gm_len,
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let instance = Instance {
			attester_addr: address!("0xc48117F22c8095504aFCa9795DCCbdA2BF5FBc73"),
			msg:
			"Ranked-choice voting is the single most important democracy reform needed in the US".to_string(),
			gm_val: "Binius".to_string(),
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
}
