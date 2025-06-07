//! implement debrag script: https://rubin.io/public/pdfs/delbrag-talk-btcpp-austin-2025.pdf
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::script::{PushBytes, Script, ScriptBuf};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use bitcoin::taproot::TaprootBuilderError;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};

use bitcoin_script_stack::optimizer;
use bitvm::hash::blake3::blake3_compute_script_with_limb;

use anyhow::Result;
use bitcoin::{Amount, opcodes};
use secp256k1::Message;

/// Helper: combine scripts (by just concatenating the raw bytes).
fn combine_scripts(fragments: &[ScriptBuf]) -> ScriptBuf {
    let mut combined = Vec::new();
    for frag in fragments {
        combined.extend(frag.to_bytes());
    }
    ScriptBuf::from_bytes(combined)
}

/// Builds a script that enforces one of two commitments to a value `Xi`
/// where the prover can reveal either preimage of H(Xi₀) or H(Xi₁).
///
/// Script logic:
/// OP_SHA256
/// OP_DUP
/// <H(Xi₀)> OP_EQUAL
/// OP_NOTIF
///     <H(Xi₁)> OP_EQUALVERIFY
/// OP_ENDIF
fn build_input_script(h_xi_0: &[u8; 32], h_xi_1: &[u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SHA256)
        .push_opcode(OP_DUP)
        .push_slice(h_xi_0) // H(Xi₀)
        .push_opcode(OP_EQUAL)
        .push_opcode(OP_IF)
        .push_opcode(OP_DROP) // Always drop leftover hash
        .push_opcode(OP_ELSE)
        .push_slice(h_xi_1) // H(Xi₁)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_ENDIF)
        .into_script()
}

fn build_inputs_script(
    labels: &[([u8; 32], [u8; 32])],
    pk_musig: PublicKey,
    pk_verifier: PublicKey,
) -> (ScriptBuf, ScriptBuf) {
    let commit_inputs = {
        let mut commits = Vec::new();
        for (h_xi_0, h_xi_1) in labels.iter() {
            commits.push(build_input_script(h_xi_0, h_xi_1));
        }
        // TODO: change to musig2 of prover and verifier
        let siging =
            Builder::new().push_key(&pk_musig.into()).push_opcode(OP_CHECKSIGVERIFY).into_script(); // Assumes both signatures required in leaf context
        commits.push(siging);
        combine_scripts(&commits)
    };

    let t_cltv_value = 10;
    let timeout_branch = Builder::new()
        .push_int(t_cltv_value) // <T>
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(&pk_verifier.into()) // <Bob>
        .push_opcode(OP_CHECKSIG)
        .into_script();

    (commit_inputs, timeout_branch)
}

fn build_failgate_script(pk_musig: PublicKey, y0_hash: &[u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(y0_hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_key(&pk_musig.into())
        .push_opcode(OP_CHECKSIGVERIFY)
        .into_script()
}

fn build_refund_script(pk_prover: PublicKey, csv_n: u16) -> ScriptBuf {
    // Refund after CSV
    Builder::new()
        .push_int(csv_n as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(&pk_prover.into())
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Create a minimal sighash for demonstration
pub fn create_sighash_message(locking_script: &ScriptBuf, value: Amount) -> Message {
    let mut engine = sha256::HashEngine::default();
    engine.input(&locking_script.to_bytes());
    engine.input(&value.to_sat().to_le_bytes());
    let digest = sha256::Hash::from_engine(engine);
    Message::from_digest(digest.to_byte_array())
}

// TODO
pub fn build_input_commit_tx() {}

// TODO
pub fn build_output_commit_tx() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::musig2::simulate_musig2;
    use crate::utils::inner_from;
    use bitcoin::script::PushBytesBuf;
    use bitcoin_script::script;
    use bitvm::{execute_script, execute_script_buf};
    use secp256k1::constants::MESSAGE_SIZE;
    use serde::Serialize;

    #[test]
    fn test_single_input_script() {
        let preimage_x0 = b"label 1";
        let expected_x0_hash = sha256::Hash::hash(preimage_x0);

        let preimage_x1 = b"label 2";
        let expected_x1_hash = sha256::Hash::hash(preimage_x1);

        for input in [preimage_x0, preimage_x1] {
            println!("input {input:?}");
            let wtns = Builder::new().push_slice(input).into_script();
            let mut script_buf = wtns.to_bytes();

            let script = build_input_script(
                &expected_x0_hash.to_byte_array(),
                &expected_x1_hash.to_byte_array(),
            );
            let locking_script = combine_scripts(&[script, script! {OP_TRUE}.compile()]);
            script_buf.extend(locking_script.to_bytes());
            let res = execute_script_buf(ScriptBuf::from_bytes(script_buf));
            println!("error: {:?}", res.error);
            println!("final_stack: {:?}", res.final_stack);
            println!("last_opcode: {:?}", res.last_opcode);
            assert!(res.success);
        }
    }

    #[test]
    fn test_commit_inputs_script_builds() {
        let sk_signers = crate::musig2::generate_keys::<2>(); // prover, verifier
        let pk_signers: Vec<musig2::secp256k1::PublicKey> =
            sk_signers.iter().map(|key| key.1).collect::<Vec<_>>();
        let agg_ctx = musig2::KeyAggContext::new(pk_signers).unwrap();
        let pk_signer: musig2::secp256k1::PublicKey = agg_ctx.aggregated_pubkey();

        // Sample H(Xi₀), H(Xi₁) hashes
        let labels = vec![
            (
                sha256::Hash::hash(b"zero").to_byte_array(),
                sha256::Hash::hash(b"one").to_byte_array(),
            ),
            (
                sha256::Hash::hash(b"two").to_byte_array(),
                sha256::Hash::hash(b"three").to_byte_array(),
            ),
        ];

        let (commit_inputs, _) =
            build_inputs_script(&labels, inner_from(pk_signer), inner_from(sk_signers[1].1));
        let locking_script = combine_scripts(&[commit_inputs, script! {OP_TRUE}.compile()]);

        // Simulate a message to multi-sig
        let msg = Message::from_digest_slice(&[0xab; MESSAGE_SIZE]).unwrap();
        let sig_der = simulate_musig2(&sk_signers, &msg).unwrap();
        let mut sig_der = sig_der.serialize().to_vec();
        sig_der.push(0x01); // SIGHASH_ALL
        let sig_push = PushBytesBuf::try_from(sig_der).expect("Invalid signature for push");

        let wtns = Builder::new()
            .push_slice(&sig_push)
            .push_slice(b"three") // or two
            .push_slice(b"one") // or zero
            .into_script();

        let mut wtns = wtns.to_bytes();
        wtns.extend(locking_script.to_bytes());

        let exec_script = ScriptBuf::from_bytes(wtns);
        let res = execute_script_buf(exec_script);

        println!("error: {:?}", res.error);
        println!("final_stack: {:?}", res.final_stack);
        println!("last_opcode: {:?}", res.last_opcode);
        assert!(res.success);
    }

    #[test]
    fn test_build_failgate_script() {
        let sk_signers = crate::musig2::generate_keys::<2>(); // prover, verifier
        let pk_signers: Vec<musig2::secp256k1::PublicKey> =
            sk_signers.iter().map(|key| key.1).collect::<Vec<_>>();
        let agg_ctx = musig2::KeyAggContext::new(pk_signers).unwrap();
        let pk_signer: musig2::secp256k1::PublicKey = agg_ctx.aggregated_pubkey();

        // Simulate Y0 preimage and hash
        let y0_preimage = b"some-secret-y0";
        let y0_hash = sha256::Hash::hash(y0_preimage);

        let output_script = build_failgate_script(inner_from(pk_signer), &y0_hash.to_byte_array());

        let locking_script = combine_scripts(&[output_script, script! {OP_TRUE}.compile()]);

        let msg = Message::from_digest_slice(&[0xab; MESSAGE_SIZE]).unwrap();
        let sig_der = simulate_musig2(&sk_signers, &msg).unwrap();
        let mut sig_der = sig_der.serialize().to_vec();
        sig_der.push(0x01); // SIGHASH_ALL
        let sig_push = PushBytesBuf::try_from(sig_der).expect("Invalid signature for push");

        let wtns = Builder::new().push_slice(&sig_push).push_slice(y0_preimage).into_script();

        let mut wtns = wtns.to_bytes();
        wtns.extend(locking_script.to_bytes());

        let exec_script = ScriptBuf::from_bytes(wtns);
        let exec_info = execute_script_buf(exec_script);

        println!("error {:?}", exec_info.error);
        println!("stack {:?}", exec_info.final_stack);
        assert!(exec_info.success);
    }
}
