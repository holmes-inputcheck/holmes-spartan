extern crate libspartan;
extern crate merlin;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use curve25519_dalek::scalar::Scalar;
use std::time::{Duration, Instant};
use rand::rngs::OsRng;


fn main() {
    // specify the size of an R1CS instance

    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    let zero = Scalar::zero().to_bytes();
    let one = Scalar::one().to_bytes();

    let a = 1u32;
    let b = 1000u32;
    let x = 1u32;
    let num_range_checks = 100000;

    let num_vars = 1048576 * 2 * 2; // number of variables generated total in range checks and private data loads (18 (total intermediary variables) * 100000 + 1 (1 total private data load) * 100000)
    let num_cons = 1048576 * 2 * 2; // total number of OT triples generated during range changes (32 (OT generated per range check) * 100000 = 3200000)
    let num_non_zero_entries = 1048576 * 2 * 2;
    let num_inputs = 2; // total number of public inputs

    let i0 = Scalar::from(x - a);
    let i1 = Scalar::from(b - x);

    let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
    inputs[0] = i0.to_bytes();
    inputs[1] = i1.to_bytes();
    let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

    let size_of_decomp = 10; 
    
    let init_start = Instant::now();
    // bit decomposition of x - a
    let mut first_bit_decomp = vec![Scalar::zero().to_bytes(); size_of_decomp];
    let binary_low = format!("{:b}", x - a);
    //println!("{:?}", binary_low);


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

    /* FOR DEBUGGING;
    let mut first_bit_decomp = vec![0; size_of_decomp];
    let mut second_bit_decomp = vec![0; size_of_decomp];
    second_bit_decomp[0] = 1;
    second_bit_decomp[1] = 1;
    second_bit_decomp[2] = 1;
    second_bit_decomp[5] = 1;
    second_bit_decomp[6] = 1;
    second_bit_decomp[7] = 1;
    second_bit_decomp[8] = 1;
    second_bit_decomp[9] = 1;


    let mut vars = vec![0; num_vars];

    for i in 0..num_range_checks {
      for j in 0..size_of_decomp {
        vars[i * size_of_decomp * 2 + j] = first_bit_decomp[j];
        vars[i * size_of_decomp * 2 + size_of_decomp + j] = second_bit_decomp[j];
        println!{"{:?}", i * size_of_decomp * 2 + size_of_decomp + j};
      }
    }*/


    /*
    for var in vars {
      println!("{:?}", var);
    }*/

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
    println!("Time elapsed setting up circuit is: {:?}\n", init_duration);

    // produce public parameters
    let gen_start = Instant::now();
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);
    let gen_duration = gen_start.elapsed();
    println!("Time elapsed in generating public parameters is: {:?}\n", gen_duration);

    // ask the library to produce a synthentic R1CS instance
    let r1cs_start = Instant::now();
    //let (inst, vars, inputs) = Instance::produce_synthetic_uniform_r1cs(num_cons, num_vars, num_inputs);
    let r1cs_duration = r1cs_start.elapsed();
    println!("Time elapsed in producing R1CS instance is: {:?}\n", r1cs_duration);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);
    println!("give me a test\n");
    
    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof_start = Instant::now();
    let proof = SNARK::prove(&inst, &decomm, assignment_vars, &assignment_inputs, &gens, &mut prover_transcript);
    let proof_duration = proof_start.elapsed();
    println!("Time elapsed in proof is: {:?}", proof_duration);

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    
    let verify_start = Instant::now();
    assert!(proof
      .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
      .is_ok());

    let verify_duration = verify_start.elapsed();
    let second_proof_duration = proof_start.elapsed();
    println!("Time elapsed in verification is: {:?}", verify_duration);
    println!("Time elapsed in proof + verification is: {:?}\n", second_proof_duration);
    println!("proof verification successful!");
}

