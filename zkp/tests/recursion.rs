use stwo::core::fields::m31::M31;
use zkp::{
    recursion::{prove_base, prove_step},
    verify::verify_record,
};

#[test]
fn three_step_chain() {
    let r0 = prove_base().expect("base");
    assert_eq!(r0.counter, M31::from(0u32));
    verify_record(&r0).expect("verify base");

    let r1 = prove_step(r0).expect("step 1");
    assert_eq!(r1.counter, M31::from(1u32));
    verify_record(&r1).expect("verify step 1");

    let r2 = prove_step(r1).expect("step 2");
    assert_eq!(r2.counter, M31::from(2u32));
    verify_record(&r2).expect("verify step 2");

    assert_eq!(
        r2.circuit_proof.claim.output_values[0],
        M31::from(2u32).into(),
        "claim output[0] must equal counter",
    );
}
