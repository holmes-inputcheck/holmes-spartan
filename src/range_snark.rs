#![feature(int_log)]
extern crate libspartan;
extern crate merlin;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use curve25519_dalek::scalar::Scalar;
use std::time::{Duration, Instant};
use rand::rngs::OsRng;
use std::fs::File;
use std::io::prelude::*;
use core::cmp::max;
use rayon::prelude::*;

fn log2u(n: u32) -> usize {
  n.ilog2().try_into().unwrap()
}


fn main() -> std::io::Result<()> {
  let a = 1;
  let b_list = vec![255, 4095, 65535, 1048575, 16777215];
  let x = 1;
  let num_range_checks = vec![100000];

  let num_vars = vec![2097152, 4194304, 4194304, 8388608, 8388608]; // number of variables generated total in range checks and private data loads (18 (total intermediary variables) * 100000 + 1 (1 total private data load) * 100000)
  let num_cons = vec![2097152, 4194304, 4194304, 8388608, 8388608];  // total number of OT triples generated during range changes (32 (OT generated per range check) * 100000 = 3200000)
  let num_non_zero_entries = vec![4194304, 8388608, 8388608, 8388608, 16777216];

  let num_inputs = 2; // total number of public inputs

  for num_range_check in num_range_checks {
    let mut output = File::create("range_check_".to_owned() + &num_range_check.to_string() + "_snark.txt")?;
    writeln!(output, "DecompSize,2party,6party,10party");

    let mut it = 0;
    for b in &b_list {
      let times = run_snark_range(a, *b, x, num_range_check, num_vars[it], num_cons[it], num_non_zero_entries[it], num_inputs);
      writeln!(output, "{}", times.join(","));
      it += 1;
    }
  }

  Ok(())
  
}

fn run_snark_range(a: u32, b: u32, x: u32, num_range_checks: usize, num_vars: usize, num_cons: usize, num_non_zero_entries: usize, num_inputs: usize) -> Vec<String> {
  let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

  let zero = Scalar::zero().to_bytes();
  let one = Scalar::one().to_bytes();

  let i0 = Scalar::from(x - a);
  let i1 = Scalar::from(b - x);

  let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
  inputs[0] = i0.to_bytes();
  inputs[1] = i1.to_bytes();
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

  let size_of_decomp = log2u(b - a) + 1; 
  
  let init_start = Instant::now();
  // bit decomposition of x - a
  let mut first_bit_decomp = vec![Scalar::zero().to_bytes(); size_of_decomp];
  let binary_low = format!("{:b}", x - a);
  println!("Running {:?} range checks with decomposition size 2^{:?} in SNARK", num_range_checks, size_of_decomp);
  //println!("num vars {:?} num cons {:?} num nonzero {:?}", num_vars, num_cons, num_non_zero_entries);


  for (i, c) in binary_low.chars().rev().enumerate() {
    if c == '0' {
      first_bit_decomp[i] = zero;
    } else if c == '1' {
      first_bit_decomp[i] = one;
    }
  }

  //println!("first bit decomp {:?}", first_bit_decomp);


  // bit decomposition of b - x
  let mut second_bit_decomp = vec![Scalar::zero().to_bytes(); size_of_decomp];

  let binary_high = format!("{:b}", b - x);

  for (i, c) in binary_high.chars().rev().enumerate() {
    if c == '0' {
      second_bit_decomp[i] = zero;
    } else if c == '1' {
      second_bit_decomp[i] = one;
    }
  }

  // initialize the 100000 * 2 bit decompositions for 100000 range checks
  let mut vars = vec![Scalar::zero().to_bytes(); num_vars];

  for i in 0..num_range_checks {
    for j in 0..size_of_decomp {
      vars[i * size_of_decomp * 2 + j] = first_bit_decomp[j];
    }

    for j in 0..size_of_decomp {
      vars[i * size_of_decomp * 2 + size_of_decomp + j] = second_bit_decomp[j];
    }
  }

  let end = num_range_checks * size_of_decomp * 2;
  
  // perform bit testing here

  // constraint i: Zi * Zi - Zi = 0

  for i in 0..end {
    A.push((i, i, one));
    B.push((i, i, one));
    C.push((i, i, one));
  }


  // perform the bit summation check here
  let base = 2u32;
  for i in 0..num_range_checks {
    for j in 0..size_of_decomp {
      A.push((end + 2 * i, i * size_of_decomp * 2 + j, Scalar::from(base.pow(j.try_into().unwrap()) as u32).to_bytes())); // Z_0 + 2*Z_1 + 4 * Z_2 + ... + 2^9 * Z_9
      B.push((end + 2 * i, num_vars, one)); // (Z_0 + 2*Z_1 + 4 * Z_2 + ... + 2^9 * Z_9) * 1
      C.push((end + 2 * i, num_vars + 1, one)); // (Z_0 + 2*Z_1 + 4 * Z_2 + ... + 2^9 * Z_9) * 1 - I_0 = 0
    }
    
    for j in 0..size_of_decomp {
      A.push((end + 2 * i + 1, i * size_of_decomp * 2 + size_of_decomp + j, Scalar::from(base.pow(j.try_into().unwrap()) as u32).to_bytes())); // Z_10 + 2*Z_11 + ... + 2^9*Z_19
      B.push((end + 2 * i + 1, num_vars, one)); // (Z_10 + 2*Z_11 + ... + 2^9*Z_19) * 1 
      C.push((end + 2 * i + 1, num_vars + 2, one)); // (Z_10 + 2*Z_11 + ... + 2^9*Z_19) * 1  - I_1 = 0
    }
  }
  

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();
  let assignment_vars = VarsAssignment::new(&vars).unwrap();
  let init_duration = init_start.elapsed();

  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert!(res.unwrap(), "should be satisfied");
  //println!("is satisfied!");
  
  //println!("Number of variables {:?}\nNumber of constraints {:?}\nNumber of inputs {:?}\n", num_vars, num_cons, num_inputs);
  //println!("Time elapsed setting up circuit is: {:?}\n", init_duration);

  // produce public parameters
  let gen_start = Instant::now();
  let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
  let gen_duration = gen_start.elapsed();
  //println!("Time elapsed in generating public parameters is: {:?}\n", gen_duration);

  // create a commitment to the R1CS instance
  let (comm, decomm) = SNARK::encode(&inst, &gens);
  //println!("Generated commitment\n");

  // produce a proof of satisfiability
  let mut prover_transcript = Transcript::new(b"snark_example");
  let proof_start = Instant::now();
  let proof = SNARK::prove(&inst, &comm, &decomm, assignment_vars, &assignment_inputs, &gens, &mut prover_transcript);
  let proof_duration = proof_start.elapsed();
  //println!("Time elapsed in proof is: {:?}", proof_duration);

  // verify the proof of satisfiability

  // run 1 verification
  let mut v_duration_1 = Duration::new(0, 0);
  {
      let mut first_verifier_transcript = Transcript::new(b"snark_example");
      let verify_start = Instant::now();
      assert!(proof
      .verify(&comm, &assignment_inputs, &mut first_verifier_transcript, &gens)
      .is_ok());
      v_duration_1 = verify_start.elapsed();
  }
  //println!("1 verifier time: {:?}", v_duration_1);

  // run 6 verifications in parallel, retrieve max
  let mut v_duration_6 = Duration::new(0, 0);
  {
      let mut verifier_transcripts_6 = Vec::with_capacity(6);
      for i in 0..6 {
          let mut verifier_transcript = Transcript::new(b"snark_example");
          verifier_transcripts_6.push(verifier_transcript);
      }
      v_duration_6 = verifier_transcripts_6
      .par_iter_mut()
      .map(|mut v| {
          let verify_start = Instant::now();
          assert!(proof
          .verify(&comm, &assignment_inputs, &mut v, &gens)
          .is_ok());
          let verify_duration = verify_start.elapsed();
          //println!("Time elapsed in verification is: {:?}", verify_duration);
          verify_duration
      })
      .reduce(|| Duration::new(0, 0), |x, y| max(x, y));
  }
  //println!("6 verifier time: {:?}", v_duration_6);

  // run 10 verifications in parallel, retrieve max
  let mut v_duration_10 = Duration::new(0, 0);
  {
      let mut verifier_transcripts_10 = Vec::with_capacity(10);
      for i in 0..10 {
          let mut verifier_transcript = Transcript::new(b"snark_example");
          verifier_transcripts_10.push(verifier_transcript);
      }
      v_duration_10 = verifier_transcripts_10
      .par_iter_mut()
      .map(|mut v| {
          let verify_start = Instant::now();
          assert!(proof
          .verify(&comm, &assignment_inputs, &mut v, &gens)
          .is_ok());
          let verify_duration = verify_start.elapsed();
          //println!("Time elapsed in verification is: {:?}", verify_duration);
          verify_duration
      })
      .reduce(|| Duration::new(0, 0), |x, y| max(x, y));
  }
  //println!("10 verifier time: {:?}", v_duration_10);

  //println!("proof verification successful!");

  let two_party_duration = init_duration + proof_duration + v_duration_1;
  let six_party_duration = init_duration + proof_duration + v_duration_6;
  let ten_party_duration = init_duration + proof_duration + v_duration_10;

  let two_party_str = (two_party_duration.as_millis() as f64 / 1000.0).to_string();
  let six_party_str = (six_party_duration.as_millis() as f64 / 1000.0).to_string();
  let ten_party_str = (ten_party_duration.as_millis() as f64 / 1000.0).to_string();

  let result = vec![size_of_decomp.to_string(),
    two_party_str, 
    six_party_str, 
    ten_party_str];

  result

}