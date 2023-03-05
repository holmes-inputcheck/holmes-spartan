extern crate libspartan;
extern crate merlin;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use curve25519_dalek::scalar::Scalar;
use std::time::{Duration, Instant};
use rand::rngs::OsRng;
use rand::Rng;
use std::fs::File;
use std::io::prelude::*;
use core::cmp::max;
use rayon::prelude::*;

const k : usize = 200; // r or number of dimensions in the paper

fn main() -> std::io::Result<()> {
    // specify the size of an R1CS instance
    let num_jls = vec![1000, 2000];
    let dim_sizes = vec![(1, 10), (4, 10), (4, 50)];
    let num_vars = vec![1048576 * 2 * 2, 1048576 *  2 * 2 * 2]; // number of variables generated total in JL and private data loads
    let num_cons = vec![1048576 * 2 * 2, 1048576 *  2 * 2 * 2]; // total number of OT triples generated during JL
    let num_non_zero_entries = vec![1048576 * 2 * 2, 1048576 * 2 * 2 * 2];
    let num_inputs = 4 * k + 2; // total number of public inputs

    let mut out_it = 0;
    for num_jl in num_jls {
        let mut output = File::create("jl_".to_owned() + &num_jl.to_string() + "_snark.txt")?;
        writeln!(output, "NumDims,SizeOfEachDim,2party,6party,10party");
        
        for it in 0..3 {
            let times = run_snark_chi(dim_sizes[it].0, dim_sizes[it].1, num_jl, num_vars[out_it], num_cons[out_it], num_inputs, num_non_zero_entries[out_it]);
            writeln!(output, "{}", times.join(","));
        }
        out_it += 1;
    }

    Ok(())
    
  }

  fn run_snark_chi(num_dims_u32: u32, size_of_each_dimension_u32: u32, num_jls: usize, num_vars: usize, num_cons: usize, num_inputs: usize, num_non_zero_entries: usize) -> Vec<String> {
    let zero = Scalar::zero().to_bytes();
    let one = Scalar::one().to_bytes();
    let prime: u64 = 4611686018427322369; //prime is the quicksilver prime

    let mut rng = rand::thread_rng();

    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    let num_dims = num_dims_u32;

    // compute the one-hot encoding of (1, 1, 1, ... , 1) where the number of parameters is num_dims
    // up to num_jls times
    let size_of_each_dimension = Scalar::from(size_of_each_dimension_u32);

    println!("Running {:?} JL checks with {:?} dimensions of size {:?} in SNARK", num_jls, num_dims, size_of_each_dimension_u32);

    let i0_u64: u64 = rng.gen_range(1u64, prime);
    let i0 = Scalar::from(i0_u64); // compute some random a to test a^2 mod p
    let i1 = Scalar::from(7u32); // QNR 7
    let key1 = vec![Scalar::from(rng.gen_range(1u64, prime)); k];
    let key2 = vec![Scalar::from(rng.gen_range(1u64, prime)); k];
    let key3 = vec![Scalar::from(rng.gen_range(1u64, prime)); k];
    let key4 = vec![Scalar::from(rng.gen_range(1u64, prime)); k];

    let mut inputs = vec![Scalar::zero().to_bytes(); num_inputs];
    for i in 0..k {
        inputs[4*i] = key1[i].to_bytes();
        inputs[4*i + 1] = key2[i].to_bytes();
        inputs[4*i + 2] = key3[i].to_bytes();
        inputs[4*i + 3] = key4[i].to_bytes();
    }
    inputs[4*k] = i0.to_bytes(); // witness a
    inputs[4*k + 1] = i1.to_bytes(); // QNR 7
    let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

    let mut one_hot_encoding_sample = Scalar::zero();
    for i in 0..num_dims {
        let mut multiplier = Scalar::one();
        for j in 1..num_dims {
            multiplier = multiplier * size_of_each_dimension;
        }
        one_hot_encoding_sample = one_hot_encoding_sample + multiplier * Scalar::one();
    }

    let one_hot_encoding_sample_sq = one_hot_encoding_sample * one_hot_encoding_sample;
    let one_hot_encoding_sample_cu = one_hot_encoding_sample_sq * one_hot_encoding_sample;

    let init_start = Instant::now();
    // compute the PRF

    // initialize the JLs
    let mut vars = vec![Scalar::zero().to_bytes(); num_vars];

    let c = 12;
    let end = c*k*num_jls;
    for i in 0..num_jls {
        for j in 0..k {
            vars[c * i * j] = one_hot_encoding_sample.to_bytes(); // one hot encoding input
            vars[c * i * j + 1] = one_hot_encoding_sample_sq.to_bytes(); 
            vars[c * i * j + 2] = one_hot_encoding_sample_cu.to_bytes();
            vars[c * i * j + 3] = (one_hot_encoding_sample * key2[j]).to_bytes();
            vars[c * i * j + 4] = (one_hot_encoding_sample_sq * key3[j]).to_bytes();
            vars[c * i * j + 5] = (one_hot_encoding_sample_cu * key4[j]).to_bytes();
            let prf = one_hot_encoding_sample * key2[j]  +
            one_hot_encoding_sample_sq * key3[j] +
            one_hot_encoding_sample_cu * key4[j] + key1[j];
            vars[c * i * j + 6] = prf.to_bytes();
            vars[c * i * j + 7] = one;
            vars[c * i * j + 8] = Scalar::from(7u32 * 1u32).to_bytes();
            vars[c * i * j + 9] = (prf * Scalar::from(7u32 * 1u32)).to_bytes();
            vars[c * i * j + 10] = (Scalar::zero() * prf).to_bytes();
            vars[c * i * j + 11] = (i0 * i0).to_bytes();
            vars[end + i * j] = zero; // bit is quadratic residue

        }
    }
    
    let inp_start = num_vars + 1;

    
    // compute the PRF 

    let mut cons_iter = 0;
    for i in 0..num_jls {
        for j in 0..k {
            
            // inp * inp - Z1 = 0 (Z1 = inp^2)
            A.push((cons_iter, c*i*j, one));
            B.push((cons_iter, c*i*j, one));
            C.push((cons_iter, c*i*j + 1, one)); 
            cons_iter += 1;

            
            // inp * Z1 - Z2 = 0 (Z2 = inp^3)
            A.push((cons_iter, c*i*j, one));
            B.push((cons_iter, c*i*j + 1, one));
            C.push((cons_iter, c*i*j + 2, one)); 
            cons_iter += 1;

            
            // inp * key2[j] - Z3 = 0
            A.push((cons_iter, c*i*j, one));
            B.push((cons_iter, inp_start + 4 * j + 1, one));
            C.push((cons_iter, c*i*j + 3, one));
            cons_iter += 1;

            // inp^2 * key3[j] - Z4 = 0
            A.push((cons_iter, c*i*j + 1, one));
            B.push((cons_iter, inp_start + 4 * j + 2, one));
            C.push((cons_iter, c*i*j + 4, one));
            cons_iter += 1;

            // inp^3 * key4[j] - Z5 = 0
            A.push((cons_iter, c*i*j + 2, one));
            B.push((cons_iter, inp_start + 4 * j + 3, one));
            C.push((cons_iter, c*i*j + 5, one));
            cons_iter += 1;

            
            // 1 * (key1[j] + Z3 + Z4 + Z5) - Z6 = 0
            
            A.push((cons_iter, num_vars, one));
            B.push((cons_iter, inp_start + 4 * j, one));
            B.push((cons_iter, c*i*j + 3, one));
            B.push((cons_iter, c*i*j + 4, one));
            B.push((cons_iter, c*i*j + 5, one));
            C.push((cons_iter, c*i*j + 6, one));
            cons_iter += 1;
        }
    }

    // bit test
    
    
    for i in 0..num_jls {
        for j in 0..k {
            A.push((cons_iter, end + i * j, one));
            B.push((cons_iter, end + i * j, one));
            C.push((cons_iter, end + i * j, one));
            cons_iter += 1;
        }
    }

    
    // compute the ZK right sum
    
    for i in 0..num_jls {
        for j in 0..k {
            // 1 * (b + Z7) - 1 = 0
            
            A.push((cons_iter, num_vars, one));
            B.push((cons_iter, end + i * j, one));
            B.push((cons_iter, c*i*j + 7, one));
            C.push((cons_iter, num_vars, one));
            cons_iter += 1;

            
            // QNR * Z7 - Z8 = 0
            A.push((cons_iter, inp_start + 4 * k + 1, one));
            B.push((cons_iter, c*i*j + 7, one));
            C.push((cons_iter, c*i*j + 8, one));
            cons_iter += 1;

            
            
            // Z6 * Z8 - Z9 = 0 (Z9 is the RHS)
            A.push((cons_iter, c*i*j + 6, one));
            B.push((cons_iter, c*i*j + 8, one));
            C.push((cons_iter, c*i*j + 9, one));
            cons_iter += 1;
        }
    }

    // compute the ZK left sum
    
    
    for i in 0..num_jls {
        for j in 0..k {
            // Z6 * b - Z10 = 0
            A.push((cons_iter, c*i*j + 6, one));
            B.push((cons_iter, end + i * j, one));
            C.push((cons_iter, c*i*j + 10, one));
            cons_iter += 1;
        }
    }

    // final ZK check (not correct, add Z11 just to approximate the benchmark
    
    for i in 0..num_jls {
        for j in 0..k {
            // a * a - Z11 = 0
            A.push((cons_iter, inp_start + 4 * k, one));
            B.push((cons_iter, inp_start + 4 * k, one));
            C.push((cons_iter, c*i*j + 11, one));
            cons_iter += 1;
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

    // ask the library to produce a synthentic R1CS instance
    let r1cs_start = Instant::now();
    //let (inst, vars, inputs) = Instance::produce_synthetic_uniform_r1cs(num_cons, num_vars, num_inputs);
    let r1cs_duration = r1cs_start.elapsed();
    //println!("Time elapsed in producing R1CS instance is: {:?}\n", r1cs_duration);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);
    
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

    let result = vec![num_dims_u32.to_string(),
        size_of_each_dimension_u32.to_string(),
        two_party_str, 
        six_party_str, 
        ten_party_str];

    result
}
