//! SMPC engine simulation environment under ideal functionality
use delbrag::{
    Circuit, Error,
    Gate,
    simulate,
};

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

    for in_a in vec![true, false] {
        for in_b in vec![true, false] {
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
    let program = Circuit::new(
        vec![
            Gate::InContrib,
            Gate::InEval,
            Gate::And(0, 1),
            Gate::Not(2),
        ],
        vec![3],
    );
    for in_a in vec![true, false] {
        for in_b in vec![true, false] {
            let input_a = vec![in_a];
            let input_b = vec![in_b];
            let result = simulate(&program, &input_a, &input_b)?;
            assert_eq!(
                result,
                vec![
                    !(in_a & in_b),
                ]
            )
        }
    }
    Ok(())
}

fn main() {
    and(10).unwrap();
    xor(10).unwrap();
    misc().unwrap();
    nand().unwrap()    
}
