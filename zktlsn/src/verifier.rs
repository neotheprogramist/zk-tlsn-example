use crate::{Result, error::ZkTlsnError};

// bb 5.0 emits solidity verifiers with PAIRING_POINTS_SIZE=8 (was 16 in bb 4.x).
const PAIRING_POINTS_SIZE: usize = 8;

pub fn validate_generated_solidity_verifier(source: &str, num_public_inputs: usize) -> Result<()> {
    let expected_public_inputs = num_public_inputs + PAIRING_POINTS_SIZE;
    [
        (
            format!("uint256 constant NUMBER_OF_PUBLIC_INPUTS = {expected_public_inputs};"),
            "verifier constant `NUMBER_OF_PUBLIC_INPUTS`",
        ),
        (
            format!("publicInputsSize: uint256({expected_public_inputs})"),
            "verification key `publicInputsSize`",
        ),
        (
            String::from(
                "require(publicInputs.length == vk.publicInputsSize - PAIRING_POINTS_SIZE, Errors.PublicInputsLengthWrong());",
            ),
            "public input arity guard",
        ),
        (
            String::from(
                "function verify(bytes calldata _proof, bytes32[] calldata _publicInputs)",
            ),
            "verifier interface",
        ),
    ]
    .into_iter()
    .try_for_each(|(snippet, label)| ensure_contains(source, &snippet, label))
}

fn ensure_contains(source: &str, snippet: &str, label: &'static str) -> Result<()> {
    source
        .contains(snippet)
        .then_some(())
        .ok_or_else(|| ZkTlsnError::InvalidInput {
            context: "solidity verifier",
            details: format!("missing {label}: `{snippet}`"),
        })
}
