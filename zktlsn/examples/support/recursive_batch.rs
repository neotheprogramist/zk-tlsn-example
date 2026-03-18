use anyhow::{Context, Result, ensure};
use zktlsn::{
    KeccakProof, RecursiveCircuit, RecursiveState, SignedTransferTicket, TicketSigner,
    prove_keccak_circuit, state_from_public_inputs, sync_recursive_circuit,
};

const MAX_SETTLEMENT_TRANSFERS: usize = 4;

#[derive(Debug, Clone)]
pub struct SettlementBundle {
    pub keccak_proof: KeccakProof,
    pub state: RecursiveState,
}

pub fn generate_settlement_bundle(tickets: &[SignedTransferTicket]) -> Result<SettlementBundle> {
    ensure!(
        !tickets.is_empty(),
        "settlement requires at least one signed ticket"
    );
    ensure!(
        tickets.len() <= MAX_SETTLEMENT_TRANSFERS,
        "settlement currently supports at most {MAX_SETTLEMENT_TRANSFERS} transfers"
    );

    let expected_to_user_id = tickets[0].to_user_id;
    ensure!(
        tickets
            .iter()
            .all(|ticket| ticket.to_user_id == expected_to_user_id),
        "all settlement tickets must target the same to_user_id"
    );
    let _total = tickets.iter().try_fold(0u64, |total, ticket| {
        total
            .checked_add(ticket.amount)
            .context("settlement total amount overflow")
    })?;

    sync_recursive_circuit().context("failed to compile settlement circuit")?;

    let signer = TicketSigner::from_env_or_default().context("failed to load ticket signer")?;
    let padding_ticket = signer
        .sign_padding_ticket()
        .context("failed to build settlement padding ticket")?;

    let mut slot_tickets = tickets.to_vec();
    while slot_tickets.len() < MAX_SETTLEMENT_TRANSFERS {
        slot_tickets.push(padding_ticket.clone());
    }

    let keccak_proof = prove_keccak_circuit(
        RecursiveCircuit::Recursive,
        &settlement_prover_toml(tickets, &slot_tickets),
    )
    .context("failed to generate settlement EVM proof")?;
    let state = state_from_public_inputs(
        &keccak_proof
            .public_inputs_hex()
            .into_iter()
            .collect::<Vec<_>>(),
    )
    .context("failed to parse settlement public inputs")?;

    Ok(SettlementBundle {
        keccak_proof,
        state,
    })
}

fn settlement_prover_toml(
    real_tickets: &[SignedTransferTicket],
    slot_tickets: &[SignedTransferTicket],
) -> String {
    let enabled_values = (0..slot_tickets.len())
        .map(|index| {
            if index < real_tickets.len() {
                "true".to_string()
            } else {
                "false".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let tx_ids = slot_tickets
        .iter()
        .map(|ticket| format!("\"{}\"", ticket.tx_id))
        .collect::<Vec<_>>()
        .join(", ");
    let to_user_ids = slot_tickets
        .iter()
        .map(|ticket| format!("\"{}\"", ticket.to_user_id))
        .collect::<Vec<_>>()
        .join(", ");
    let amounts = slot_tickets
        .iter()
        .map(|ticket| format!("\"{}\"", ticket.amount))
        .collect::<Vec<_>>()
        .join(", ");
    let signatures = slot_tickets
        .iter()
        .map(|ticket| {
            ticket
                .signature_array()
                .map(|signature| format_byte_array(&signature))
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("ticket signatures should be 64 bytes")
        .join(",\n");

    format!(
        "enabled = [{enabled_values}]\n\
tx_ids = [{tx_ids}]\n\
to_user_ids = [{to_user_ids}]\n\
amounts = [{amounts}]\n\
signatures = [\n{signatures}\n]\n"
    )
}

fn format_byte_array<const N: usize>(bytes: &[u8; N]) -> String {
    let values = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("  [{values}]")
}
