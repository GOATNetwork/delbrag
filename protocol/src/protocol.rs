//! implement debrag script: https://rubin.io/public/pdfs/delbrag-talk-btcpp-austin-2025.pdf
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use bitcoin::script::{PushBytes, Script, ScriptBuf};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use bitcoin::taproot::TaprootBuilderError;
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};

use bitcoin_script_stack::optimizer;
use bitvm::hash::blake3::blake3_compute_script_with_limb;

use anyhow::Result;

/// Helper: combine scripts (by just concatenating the raw bytes).
fn combine_scripts(fragments: &[ScriptBuf]) -> ScriptBuf {
    let mut combined = Vec::new();
    for frag in fragments {
        combined.extend(frag.to_bytes());
    }
    ScriptBuf::from_bytes(combined)
}

fn commit_inputs_script(
    labels: &[([u8; 32], [u8; 32])],
    prover_pk: PublicKey,
    verifier_pk: PublicKey,
) -> ScriptBuf {
    let mut commit_inputs = {
        let mut commits = Vec::new();
        for (h_xi_0, h_xi_1) in labels.iter() {
            let commit_inputs = Builder::new()
                .push_opcode(OP_SHA256)
                .push_opcode(OP_DUP)
                .push_slice(h_xi_0) // H(Xi₀)
                .push_opcode(OP_EQUAL)
                .push_opcode(OP_NOTIF)
                .push_slice(h_xi_1) // H(Xi₁)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_ENDIF)
                .into_script();
            commits.push(commit_inputs);
        }

        let siging = Builder::new()
            .push_key(&prover_pk.into()) // <Alice>
            .push_key(&verifier_pk.into()) // <Bob>
            .push_opcode(OP_CHECKSIG)
            .into_script(); // Assumes both signatures required in leaf context

        commits.push(siging);
        commits
    };

    let t_cltv_value = 10;
    let timeout_branch = Builder::new()
        .push_int(t_cltv_value) // <T>
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(&verifier_pk.into()) // <Bob>
        .push_opcode(OP_CHECKSIG)
        .into_script();

    commit_inputs.push(timeout_branch);
    combine_scripts(&commit_inputs)
}

fn generate_keys() -> (SecretKey, SecretKey) {
    // Simulate keypairs for Alice and Bob
    let prover_sk = SecretKey::new(&mut OsRng);
    let verifier_sk = SecretKey::new(&mut OsRng);
    //let alice_pk = PublicKey::from_secret_key(&secp, &alice_sk);
    //let bob_pk = PublicKey::from_secret_key(&secp, &bob_sk);
    (prover_sk, verifier_sk)
}

fn commit_output_script(
    prover_pk: PublicKey,
    verifier_pk: PublicKey,
) -> Result<(ScriptBuf, ScriptBuf)> {
    // Simulate Y0 preimage and hash
    let y0_preimage = b"some-secret-y0";
    let y0_hash = sha256::Hash::hash(y0_preimage);

    // CSV locktime
    let csv_n: u16 = 10;

    // Punishment
    let punishment_script = Builder::new()
        .push_slice(y0_hash.to_byte_array())
        .push_opcode(OP_SHA256)
        .push_opcode(OP_EQUALVERIFY)
        .push_key(&verifier_pk.into())
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_key(&prover_pk.into())
        .push_opcode(OP_CHECKSIG)
        .into_script();

    // Refund after CSV
    let refund_script = Builder::new()
        .push_int(csv_n as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(&prover_pk.into())
        .push_opcode(OP_CHECKSIG)
        .into_script();

    Ok((punishment_script, refund_script))
}

//// Internal key: MuSig2(Alice, Bob) simulation (we just pick one key here)
//    let internal_key = Keypair::new(&secp, &mut OsRng);
//    let internal_pk = internal_key.public_key();
//
//    // Create taproot spend info
//    let spend_info = TaprootBuilder::new()
//        .add_leaf(0, punishment_script.clone())?
//        .add_leaf(0, refund_script.clone())?
//        .finalize(&secp, internal_pk.into()).unwrap();
//
//    let taproot_output_key = spend_info.output_key();
//
//    println!("taproot_output_key: {:?}", taproot_output_key);
//    Ok(spend_info)

#[cfg(test)]
mod tests {
    use super::*;
    use bitvm::execute_script_buf;
    #[test]
    fn test_commit_script() {
        let secp = Secp256k1::new();
        let (prover_sk, verifier_sk) = generate_keys();
        let prover_pk = PublicKey::from_secret_key(&secp, &prover_sk);
        let verifier_pk = PublicKey::from_secret_key(&secp, &verifier_sk);

        let output_script = commit_output_script(prover_pk.clone(), verifier_pk.clone()).unwrap();

        let punishment_execution = execute_script_buf(output_script.0.clone());
        println!("error {:?}", punishment_execution.error);
        println!("stack {:?}", punishment_execution.final_stack);
        assert!(punishment_execution.success);
    }
}
