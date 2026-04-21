use garbled_circuit::circuit::{BinaryCircuit, CircuitBuilder};

use crate::utils::bytes_to_bits_be;

/// Returns the `BinaryCircuit` which implements addition modulo a constant `prime` of two
///  binary values of bit length `size`
///
/// The first input is set as the gabler's input and the next input is
/// set as the evaluator's input
pub fn build_mod_add_circut(
    size: usize,
    prime_bytes: [u8; 32],
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let mut pbin = bytes_to_bits_be(&prime_bytes);

    if size + 1 > pbin.len() {
        pbin.extend_from_slice(&vec![false; (size + 1) - pbin.len()]);
    }

    let ps = pbin
        .iter()
        .map(|&v| builder.constant(v))
        .collect::<Vec<_>>();

    let x = builder.new_inputs(size as u16);
    let y = builder.new_inputs(size as u16);

    let add_circuit = build_ppa_circuit(size);

    let add = builder.add_circuit(&add_circuit, &[&x, &y]);

    let comp_circ = build_compare_ge_circuit(size + 1);
    let comp = builder.add_circuit(&comp_circ, &[&add, &ps]);

    let sub_circ = build_subtract_order_circuit(size + 1, prime_bytes);
    let sub = builder.add_circuit(&sub_circ, &[&add]);

    let comps = vec![comp[0]; size];

    let ifthenelse_circ = build_if_then_else_circuit(size);
    let out = builder
        .add_circuit(&ifthenelse_circ, &[&comps, &sub[..size], &add[..size]]);

    for i in out {
        builder.output(i);
    }

    builder.finish()
}

pub fn build_compare_eq_circuit(input_len: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let input1 = builder.new_inputs(input_len as u16);
    let input2 = builder.new_inputs(input_len as u16);

    let xors: Vec<u32> = input1
        .iter()
        .zip(&input2)
        .map(|(i1, i2)| builder.xor(*i1, *i2))
        .collect();

    let mut output = xors[0];

    (1..xors.len()).for_each(|i| {
        let temp1 = builder.xor(output, xors[i]);
        let temp2 = builder.and(output, xors[i]);
        output = builder.xor(temp1, temp2);
    });

    let op = builder.negate(output);
    builder.output(op);

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements subtraction of a binary value of
/// bit length `size` by a constant `prime`.
///
/// The input is set as the garbler's input
pub fn build_subtract_order_circuit(
    size: usize,
    prime_bytes: [u8; 32],
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let gin = builder.new_inputs(size as u16);

    let mut pbin = bytes_to_bits_be(&prime_bytes);

    if size > pbin.len() {
        pbin.extend_from_slice(&vec![false; size - pbin.len()]);
    }

    pbin = pbin.iter().map(|v| !*v).collect();

    let mut value = true;
    #[allow(clippy::needless_range_loop)]
    for i in 0..pbin.len() {
        let bit = pbin[i];
        let sum = bit ^ value;
        value &= bit;
        pbin[i] = sum;
        if !value {
            break;
        }
    }

    let mut pbin_ids = Vec::new();
    let mut pt = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for i in 0..pbin.len() as usize {
        let id = builder.constant(pbin[i]);
        pt.push(pbin[i]);
        pbin_ids.push(id);
    }

    let ppa_circuit = build_ppa_circuit(size);
    let ppaout = builder.add_circuit(&ppa_circuit, &[&gin, &pbin_ids]);

    (0..size).for_each(|i| {
        builder.output(ppaout[i]);
    });

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements parallel prefix adder, which
/// adds two binary values of bit length `size`.
///
/// The first input is set as the gabler's input and the next input is set as the
/// evaluator's input
pub fn build_ppa_circuit(size: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let inp1 = builder.new_inputs(size as u16);
    let inp2 = builder.new_inputs(size as u16);

    let mut g = Vec::new();
    let mut p = Vec::new();

    let mut size_log2 = size.ilog2() as usize;
    let size_diff = size - (1 << size_log2);
    if size_diff != 0 {
        size_log2 += 1;
    }

    for i in 0..size {
        p.push(builder.xor(inp1[i], inp2[i]));
        g.push(builder.and(inp1[i], inp2[i]));
    }

    let pc = p.clone();

    for step in 0..size_log2 {
        let g_to_and_1 = &g[0..size - (1usize << step)];
        let p_to_and_2 = &p[0..size - (1usize << step)];
        let p_to_and_1_2 = &p[1usize << step..size];
        let g_to_or = &g[1usize << step..size];

        let gc_to_or: Vec<u32> = g_to_and_1
            .iter()
            .zip(p_to_and_1_2)
            .map(|(x, y)| builder.and(*x, *y))
            .collect();

        let pc_after_and: Vec<u32> = p_to_and_2
            .iter()
            .zip(p_to_and_1_2)
            .map(|(x, y)| builder.and(*x, *y))
            .collect();

        let gc_after_or: Vec<u32> = g_to_or
            .iter()
            .zip(&gc_to_or)
            .map(|(x, y)| {
                let l = builder.and(*x, *y);
                let m = builder.xor(*x, *y);
                builder.xor(l, m)
            })
            .collect();

        for i in (1usize << step)..size {
            p[i] = pc_after_and[i - (1usize << step)];
            g[i] = gc_after_or[i - (1usize << step)];
        }
    }

    let g_size = g[size - 1];
    let mut g_mul_two = vec![builder.constant(false)];
    g_mul_two.extend_from_slice(&g[..size - 1]);

    let sum: Vec<u32> = pc
        .iter()
        .zip(&g_mul_two)
        .map(|(x, y)| builder.xor(*x, *y))
        .collect();

    for i in sum {
        builder.output(i);
    }

    builder.output(g_size);

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements compare ge protocol, which
/// compares two binary values of `size` bit length
///
/// If the garbler's input is `x` and the evaluator's input is `y`, the
/// circuit returns `x >= y`
pub fn build_compare_ge_circuit(size: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let x = builder.new_inputs(size as u16);
    let y = builder.new_inputs(size as u16);

    let rec_circ = build_compare_ge_rec_circuit(size, 0, size - 1);

    let ops = builder.add_circuit(&rec_circ, &[&x, &y]);

    builder.output(ops[0]);

    builder.finish()
}

/// Returns the `BinaryCircuit` which implements the recursion for
/// compare ge protocol, which compares two binary values of `size`
/// bit length
pub fn build_compare_ge_rec_circuit(
    size: usize,
    lo: usize,
    hi: usize,
) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let xvals = builder.new_inputs(size as u16);
    let yvals = builder.new_inputs(size as u16);

    assert!(lo <= hi, "impossible {lo} {hi}");

    if lo == hi {
        let a = builder.xor(xvals[lo], yvals[lo]);
        let temp = builder.and(a, yvals[lo]);
        let t = builder.negate(temp);
        builder.output(t);
        builder.output(a);
        return builder.finish();
    }

    let m = lo + (hi - lo) / 2;
    let circ_low = build_compare_ge_rec_circuit(size, lo, m);
    let circ_high = build_compare_ge_rec_circuit(size, m + 1, hi);

    let lowout = builder.add_circuit(&circ_low, &[&xvals, &yvals]);
    let highout = builder.add_circuit(&circ_high, &[&xvals, &yvals]);

    let (subres_l, diff_l) = (lowout[0], lowout[1]);
    let (subres_h, diff_h) = (highout[0], highout[1]);

    let ifelse_circ = build_if_then_else_circuit(1);
    let subres = builder
        .add_circuit(&ifelse_circ, &[&[diff_h], &[subres_h], &[subres_l]]);

    let mut diff = builder.xor(diff_h, diff_l);
    let temp = builder.and(diff_h, diff_l);
    diff = builder.xor(temp, diff);

    builder.output(subres[0]);
    builder.output(diff);

    builder.finish()
}

/// Returns a `BinaryCircuit` which implements a batched version of `if then else`.
/// The garbler inputs contains `choice + input1`.
/// The evaluator inputs contains `input2`.
/// If choice is true, then `input1` is the output. Else, the output is `input2`.
pub fn build_if_then_else_circuit(size: usize) -> BinaryCircuit {
    let mut builder = CircuitBuilder::new();

    let choice = builder.new_inputs(size as u16);
    let gin = builder.new_inputs(size as u16);
    let ein = builder.new_inputs(size as u16);

    let r: Vec<u32> = gin
        .iter()
        .zip(&ein)
        .zip(&choice)
        .map(|((x, y), c)| {
            let z = builder.xor(*x, *y);
            let d = builder.and(z, *c);
            builder.xor(d, *y)
        })
        .collect();

    for i in r {
        builder.output(i);
    }

    builder.finish()
}

#[cfg(test)]
mod tests {
    use group::ff::{Field, PrimeField};
    use pasta_curves::pallas::Scalar;
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{
        circuits::{build_mod_add_circut, bytes_to_bits_be},
        eval::evaluate,
    };

    #[test]
    fn test_mod_add() {
        let mut rng = StdRng::from_entropy();

        let s1 = Scalar::random(&mut rng);
        let s2 = Scalar::random(&mut rng);

        let s1_bits = bytes_to_bits_be(&s1.to_repr());
        let s2_bits = bytes_to_bits_be(&s2.to_repr());

        // let mut outval = Scalar::ZERO;
        // let two = Scalar::ONE + Scalar::ONE;
        // let mut twomul = Scalar::ONE;

        // for &i in &s1_bits {
        //     if i {
        //         outval += twomul;
        //     }
        //     twomul *= two;
        // }

        // println!("s1: {:?}", outval);

        let mut prime_bytes = hex::decode(&Scalar::MODULUS[2..]).unwrap();
        prime_bytes.reverse();

        let circuit = build_mod_add_circut(
            s1_bits.len(),
            prime_bytes.try_into().unwrap(),
        );

        let out = evaluate(&circuit, &[&s1_bits, &s2_bits]);

        let mut outval = Scalar::ZERO;
        let two = Scalar::ONE + Scalar::ONE;
        let mut twomul = Scalar::ONE;

        for i in out {
            if i {
                outval += twomul;
            }
            twomul *= two;
        }

        println!("a : {s1:?}");
        println!("b : {s2:?}");
        println!("id: {:?}", s1 + s2);
        println!("re: {outval:?}");
    }
}
