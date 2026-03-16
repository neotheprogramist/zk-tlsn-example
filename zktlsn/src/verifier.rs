use noir::barretenberg::utils::get_subgroup_size;

use crate::{
    error::{Result, ZkTlsnError},
    prover::load_circuit_bytecode,
};

const PAIRING_POINTS_SIZE: usize = 16;
const FORGE_LINT_DISABLE_START: &str = "/// forge-lint: disable-start(all)\n";
const FORGE_LINT_DISABLE_END: &str = "/// forge-lint: disable-end(all)\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolidityVerifierConfig {
    pub subgroup_size: u32,
    pub log_subgroup_size: u32,
    pub num_public_inputs: usize,
}

pub fn expected_solidity_verifier_config(
    num_public_inputs: usize,
) -> Result<SolidityVerifierConfig> {
    let bytecode = load_circuit_bytecode()?;
    let subgroup_size = get_subgroup_size(&bytecode, false);
    if subgroup_size == 0 || !subgroup_size.is_power_of_two() {
        return Err(ZkTlsnError::InvalidInput(format!(
            "unexpected subgroup size for Solidity verifier: {subgroup_size}"
        )));
    }

    Ok(SolidityVerifierConfig {
        subgroup_size,
        log_subgroup_size: subgroup_size.ilog2(),
        num_public_inputs,
    })
}

pub fn normalize_generated_solidity_verifier(
    source: &str,
    config: SolidityVerifierConfig,
) -> Result<String> {
    let total_public_inputs = config.num_public_inputs + PAIRING_POINTS_SIZE;
    let mut patched = source.to_string();
    patched = replace_numeric_assignment(
        &patched,
        "uint256 constant N = ",
        ";",
        config.subgroup_size as usize,
    )?;
    patched = replace_numeric_assignment(
        &patched,
        "uint256 constant LOG_N = ",
        ";",
        config.log_subgroup_size as usize,
    )?;
    patched = replace_numeric_assignment(
        &patched,
        "uint256 constant NUMBER_OF_PUBLIC_INPUTS = ",
        ";",
        total_public_inputs,
    )?;
    patched = replace_numeric_assignment(
        &patched,
        "circuitSize: uint256(",
        ")",
        config.subgroup_size as usize,
    )?;
    patched = replace_numeric_assignment(
        &patched,
        "logCircuitSize: uint256(",
        ")",
        config.log_subgroup_size as usize,
    )?;
    patched = replace_numeric_assignment(
        &patched,
        "publicInputsSize: uint256(",
        ")",
        total_public_inputs,
    )?;
    patched = replace_source_snippet(
        &patched,
        "        Honk.RelationParameters memory rp,\n",
        "        Honk.RelationParameters memory,\n",
    )?;
    Ok(with_forge_lint_disabled(&patched))
}

fn with_forge_lint_disabled(source: &str) -> String {
    let without_start = source
        .strip_prefix(FORGE_LINT_DISABLE_START)
        .unwrap_or(source);
    let without_end = without_start
        .strip_suffix(FORGE_LINT_DISABLE_END)
        .unwrap_or(without_start);

    format!(
        "{FORGE_LINT_DISABLE_START}{}\n{FORGE_LINT_DISABLE_END}",
        without_end.trim_end_matches('\n')
    )
}

fn replace_numeric_assignment(
    source: &str,
    marker: &str,
    suffix: &str,
    replacement: usize,
) -> Result<String> {
    let start = source.find(marker).ok_or_else(|| {
        ZkTlsnError::InvalidInput(format!("missing Solidity verifier marker `{marker}`"))
    })?;
    let value_start = start + marker.len();
    let relative_end = source[value_start..]
        .find(suffix)
        .ok_or_else(|| ZkTlsnError::InvalidInput(format!("missing suffix `{suffix}`")))?;
    let value_end = value_start + relative_end;

    let mut patched = String::with_capacity(source.len() + 16);
    patched.push_str(&source[..value_start]);
    patched.push_str(&replacement.to_string());
    patched.push_str(&source[value_end..]);
    Ok(patched)
}

fn replace_source_snippet(source: &str, from: &str, to: &str) -> Result<String> {
    source
        .contains(from)
        .then(|| source.replacen(from, to, 1))
        .ok_or_else(|| {
            ZkTlsnError::InvalidInput(format!("missing Solidity verifier snippet `{from}`"))
        })
}

#[cfg(test)]
mod tests {
    use super::{
        FORGE_LINT_DISABLE_END, FORGE_LINT_DISABLE_START, SolidityVerifierConfig,
        normalize_generated_solidity_verifier,
    };

    #[test]
    fn test_normalize_generated_solidity_verifier_updates_metadata() {
        let source = r#"
uint256 constant N = 1;
uint256 constant LOG_N = 32768;
uint256 constant NUMBER_OF_PUBLIC_INPUTS = 15;
function accumulateNnfRelation(
    Fr[NUMBER_OF_ENTITIES] memory p,
        Honk.RelationParameters memory rp,
    Fr[NUMBER_OF_SUBRELATIONS] memory evals,
    Fr domainSep
) internal pure {}
Honk.VerificationKey memory vk = Honk.VerificationKey({
    circuitSize: uint256(1),
    logCircuitSize: uint256(32768),
    publicInputsSize: uint256(15)
});
"#;

        let patched = normalize_generated_solidity_verifier(
            source,
            SolidityVerifierConfig {
                subgroup_size: 32768,
                log_subgroup_size: 15,
                num_public_inputs: 32,
            },
        )
        .expect("patched");

        assert!(patched.starts_with(FORGE_LINT_DISABLE_START));
        assert!(patched.ends_with(FORGE_LINT_DISABLE_END));
        assert!(patched.contains("uint256 constant N = 32768;"));
        assert!(patched.contains("uint256 constant LOG_N = 15;"));
        assert!(patched.contains("uint256 constant NUMBER_OF_PUBLIC_INPUTS = 48;"));
        assert!(patched.contains("circuitSize: uint256(32768)"));
        assert!(patched.contains("logCircuitSize: uint256(15)"));
        assert!(patched.contains("publicInputsSize: uint256(48)"));
        assert!(patched.contains("Honk.RelationParameters memory,"));
    }
}
