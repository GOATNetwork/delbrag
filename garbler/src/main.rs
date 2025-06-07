//! SMPC engine simulation environment under ideal functionality
use clap::Parser;
use wrk17::{Circuit, Error, Gate, simulate};
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 10)]
    iters: u32,

    #[arg(short, long, default_value = "and")]
    circuits: String,

    /// Fee‑rate in sat/vB (default = 1 sat/vB, plenty for Signet)
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,

    /// Network name
    #[arg(short, long, default_value = "regtest")]
    network: String,

    /// Network RRC URL
    #[arg(short, long, default_value = "http://127.0.0.1:18443")]
    rpc_url: String,

    /// RPC user
    #[arg(long, default_value = "user")]
    rpc_user: String,

    /// RPC password
    #[arg(long, default_value = "PaSsWoRd")]
    rpc_password: String,

    /// bitcoin wallet name
    #[arg(long, default_value = "alice")]
    wallet_name: String,
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

    let result = simulate(&program, &input_a, &input_b)?;

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

    let result = simulate(&program, &input_a, &input_b)?;

    let expected = vec![iterations % 2 == 0];

    assert_eq!(result, expected);

    Ok(())
}

fn misc() -> Result<(), Error> {
    let program = Circuit::new(
        vec![
            Gate::InContrib,
            Gate::InEval,
            Gate::Xor(0, 1),
            // gate 3 : !not(xor)
            Gate::Not(2),
            Gate::Not(0),
            Gate::Not(1),
            // gate 6: Xor(!a, b)
            Gate::Xor(4, 1),
            // gate 7: Xor(a, !b)
            Gate::Xor(0, 5),
            // gate 8: !Xor(a, !b)
            Gate::Not(7),
            Gate::And(0, 1),
            // gate 10: NAND(a, b)
            Gate::Not(9),
        ],
        vec![2, 3, 6, 7, 8, 10],
    );

    for in_a in [true, false] {
        for in_b in [true, false] {
            let input_a = vec![in_a];
            let input_b = vec![in_b];

            let result = simulate(&program, &input_a, &input_b)?;

            assert_eq!(
                result,
                vec![
                    in_a ^ in_b,
                    !(in_a ^ in_b),
                    (!in_a) ^ in_b,
                    in_a ^ (!in_b),
                    !(in_a ^ (!in_b)),
                    !(in_a & in_b)
                ]
            );
        }
    }
    Ok(())
}

fn nand() -> Result<(), Error> {
    let program =
        Circuit::new(vec![Gate::InContrib, Gate::InEval, Gate::And(0, 1), Gate::Not(2)], vec![3]);
    for in_a in [true, false] {
        for in_b in [true, false] {
            let input_a = vec![in_a];
            let input_b = vec![in_b];
            let result = simulate(&program, &input_a, &input_b)?;
            assert_eq!(result, vec![!(in_a & in_b),])
        }
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    match args.circuits.as_str() {
        "and" => and(args.iters).unwrap(),
        "xor" => xor(args.iters).unwrap(),
        "nand" => nand().unwrap(),
        "misc" => misc().unwrap(),
        &_ => todo!(),
    }
}
