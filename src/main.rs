//! SMPC engine simulation environment under ideal functionality
use delbrag::{
    states::{Contributor, Evaluator},
    Circuit, Error,
    Gate,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Simulates the local execution of the circuit using a 2 Party MPC protocol.
///
/// The Multi-Party Computation is performed using the full cryptographic protocol exposed by the
/// [`Contributor`] and [`Evaluator`]. The messages between contributor and evaluator are exchanged
/// using local message queues. This function thus simulates an MPC execution on a local machine
/// under ideal network conditions, without any latency or bandwidth restrictions.
pub fn simulate(
    circuit: &Circuit,
    input_contributor: &[bool],
    input_evaluator: &[bool],
) -> Result<Vec<bool>, Error> {
    let mut eval = Evaluator::new(
        circuit.clone(),
        input_evaluator,
        ChaCha20Rng::from_entropy(),
    )?;
    let (mut contrib, mut msg_for_eval) =
        Contributor::new(circuit, input_contributor, ChaCha20Rng::from_entropy())?;

    assert_eq!(contrib.steps(), eval.steps());

    for _ in 0..eval.steps() {
        let (next_state, msg_for_contrib) = eval.run(&msg_for_eval)?;
        eval = next_state;

        let (next_state, reply) = contrib.run(&msg_for_contrib)?;
        contrib = next_state;

        msg_for_eval = reply;
    }
    eval.output(&msg_for_eval)
}

fn and(iterations: u32) -> Result<(), Error> {
    let mut gates = vec![Gate::InContrib];
    let output_gates = vec![iterations * 2];
    for i in 0..iterations {
        gates.append(&mut vec![Gate::InEval, Gate::And(i * 2, i * 2 + 1)]);
    }

    let program = Circuit::new(gates, output_gates);

    let input_a = vec![true];
    let input_b = vec![true; iterations as usize];

    let result = simulate(&program, &input_a, &input_b).unwrap();

    assert_eq!(result, vec![true]);

    Ok(())
}

fn xor(iterations: u32) -> Result<(), Error> {
    let mut gates = vec![Gate::InContrib];
    let output_gates = vec![iterations * 2];
    for i in 0..iterations {
        gates.append(&mut vec![Gate::InEval, Gate::And(i * 2, i * 2 + 1)]);
    }

    let program = Circuit::new(gates, output_gates);

    let input_a = vec![true];
    let input_b = vec![true; iterations as usize];

    let result = simulate(&program, &input_a, &input_b).unwrap();

    let expected = vec![iterations % 2 == 0];

    assert_eq!(result, expected);

    Ok(())
}

fn nand(iterations: u32) -> Result<(), Error> {
    let mut gates = vec![Gate::InContrib];
    let output_gates = vec![iterations * 2];
    for i in 0..iterations {
        gates.append(&mut vec![Gate::InEval, Gate::Nand(i * 2, i * 2 + 1)]);
    }

    let program = Circuit::new(gates, output_gates);
    program.validate().unwrap();

    let input_a = vec![true];
    let input_b = vec![true; iterations as usize];

    let result = simulate(&program, &input_a, &input_b).unwrap();

    let expected = vec![iterations % 2 == 0];

    assert_eq!(result, expected);

    Ok(())
}

fn main() {
    and(10).unwrap();
    xor(10).unwrap();
    nand(2).unwrap()
}
