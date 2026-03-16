use noir::barretenberg::utils::get_subgroup_size;

use crate::{
    error::{Result, ZkTlsnError},
    prover::load_circuit_bytecode,
};

const PAIRING_POINTS_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GeneratedSolidityVerifierShape {
    subgroup_size: u32,
    log_subgroup_size: u32,
    total_public_inputs: usize,
}

pub fn validate_generated_solidity_verifier(source: &str, num_public_inputs: usize) -> Result<()> {
    let expected = expected_generated_solidity_verifier_shape(num_public_inputs)?;
    [
        (
            format!("uint256 constant N = {};", expected.subgroup_size),
            "verifier constant `N`",
        ),
        (
            format!("uint256 constant LOG_N = {};", expected.log_subgroup_size),
            "verifier constant `LOG_N`",
        ),
        (
            format!(
                "uint256 constant NUMBER_OF_PUBLIC_INPUTS = {};",
                expected.total_public_inputs
            ),
            "verifier constant `NUMBER_OF_PUBLIC_INPUTS`",
        ),
        (
            format!("circuitSize: uint256({})", expected.subgroup_size),
            "verification key `circuitSize`",
        ),
        (
            format!("logCircuitSize: uint256({})", expected.log_subgroup_size),
            "verification key `logCircuitSize`",
        ),
        (
            format!(
                "publicInputsSize: uint256({})",
                expected.total_public_inputs
            ),
            "verification key `publicInputsSize`",
        ),
        (
            String::from("if (publicInputs.length != vk.publicInputsSize - PAIRING_POINTS_SIZE) {"),
            "public input arity guard",
        ),
    ]
    .into_iter()
    .try_for_each(|(snippet, label)| ensure_contains(source, &snippet, label))
}

fn expected_generated_solidity_verifier_shape(
    num_public_inputs: usize,
) -> Result<GeneratedSolidityVerifierShape> {
    let bytecode = load_circuit_bytecode()?;
    let subgroup_size = get_subgroup_size(&bytecode, false);
    if subgroup_size == 0 || !subgroup_size.is_power_of_two() {
        return Err(ZkTlsnError::InvalidInput(format!(
            "unexpected subgroup size for Solidity verifier: {subgroup_size}"
        )));
    }

    Ok(GeneratedSolidityVerifierShape {
        subgroup_size,
        log_subgroup_size: subgroup_size.ilog2(),
        total_public_inputs: num_public_inputs + PAIRING_POINTS_SIZE,
    })
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
    use super::{expected_generated_solidity_verifier_shape, validate_generated_solidity_verifier};

    #[test]
    fn test_validate_generated_solidity_verifier_accepts_expected_source() {
        let expected = expected_generated_solidity_verifier_shape(32).expect("expected shape");
        let source = format!(
            r#"
uint256 constant N = {};
uint256 constant LOG_N = {};
uint256 constant NUMBER_OF_PUBLIC_INPUTS = {};
Honk.VerificationKey memory vk = Honk.VerificationKey({{
    circuitSize: uint256({}),
    logCircuitSize: uint256({}),
    publicInputsSize: uint256({})
}});
if (publicInputs.length != vk.publicInputsSize - PAIRING_POINTS_SIZE) {{
}}
"#,
            expected.subgroup_size,
            expected.log_subgroup_size,
            expected.total_public_inputs,
            expected.subgroup_size,
            expected.log_subgroup_size,
            expected.total_public_inputs,
        );

        validate_generated_solidity_verifier(&source, 32).expect("valid raw verifier");
    }

    #[test]
    fn test_validate_generated_solidity_verifier_rejects_mismatched_public_inputs_size() {
        let expected = expected_generated_solidity_verifier_shape(32).expect("expected shape");
        let source = format!(
            r#"
uint256 constant N = {};
uint256 constant LOG_N = {};
uint256 constant NUMBER_OF_PUBLIC_INPUTS = 47;
Honk.VerificationKey memory vk = Honk.VerificationKey({{
    circuitSize: uint256({}),
    logCircuitSize: uint256({}),
    publicInputsSize: uint256(47)
}});
if (publicInputs.length != vk.publicInputsSize - PAIRING_POINTS_SIZE) {{
}}
"#,
            expected.subgroup_size,
            expected.log_subgroup_size,
            expected.subgroup_size,
            expected.log_subgroup_size,
        );

        let error =
            validate_generated_solidity_verifier(&source, 32).expect_err("mismatched verifier");
        assert!(error.to_string().contains(
            "generated Solidity verifier is missing verifier constant `NUMBER_OF_PUBLIC_INPUTS`"
        ));
    }
}
