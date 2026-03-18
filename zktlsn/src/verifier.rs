use crate::{Result, error::ZkTlsnError};

const PAIRING_POINTS_SIZE: usize = 16;

pub fn validate_generated_solidity_verifier(source: &str, num_public_inputs: usize) -> Result<()> {
    validate_generated_solidity_verifier_for_bytecode(source, "", num_public_inputs, false)
}

pub fn validate_generated_solidity_verifier_for_bytecode(
    source: &str,
    _bytecode: &str,
    num_public_inputs: usize,
    _recursive: bool,
) -> Result<()> {
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
            String::from("if (publicInputs.length != vk.publicInputsSize - PAIRING_POINTS_SIZE) {"),
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

fn ensure_contains(source: &str, snippet: &str, label: &str) -> Result<()> {
    source.contains(snippet).then_some(()).ok_or_else(|| {
        ZkTlsnError::InvalidInput(format!(
            "generated Solidity verifier is missing {label}: `{snippet}`"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::validate_generated_solidity_verifier;

    #[test]
    fn validate_generated_solidity_verifier_accepts_expected_source() {
        let source = r#"
uint256 constant NUMBER_OF_PUBLIC_INPUTS = 51;
Honk.VerificationKey memory vk = Honk.VerificationKey({
    publicInputsSize: uint256(51)
});
function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool) {}
if (publicInputs.length != vk.publicInputsSize - PAIRING_POINTS_SIZE) {
}
"#;

        validate_generated_solidity_verifier(source, 35).expect("valid raw verifier");
    }

    #[test]
    fn validate_generated_solidity_verifier_rejects_mismatched_public_inputs_size() {
        let source = r#"
uint256 constant NUMBER_OF_PUBLIC_INPUTS = 47;
Honk.VerificationKey memory vk = Honk.VerificationKey({
    publicInputsSize: uint256(47)
});
function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool) {}
if (publicInputs.length != vk.publicInputsSize - PAIRING_POINTS_SIZE) {
}
"#;

        let error =
            validate_generated_solidity_verifier(source, 35).expect_err("mismatched verifier");
        assert!(error.to_string().contains(
            "generated Solidity verifier is missing verifier constant `NUMBER_OF_PUBLIC_INPUTS`"
        ));
    }
}
