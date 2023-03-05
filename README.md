## Setup for HOLMES Spartan benchmarking:

## On the AMI (recommended)

1. Follow the instructions [here](https://github.com/holmes-inputcheck/holmes) to start a cluster

2a. 

Either run:
```
python3 start_spartan_bench.py
```
This will require your local machine to remain connected to SSH for around 3 hours to finish all the benchmarking

2b. Or you can ssh into the AMI instance, and then run a screen. Then, you can run the tests on the cluster without being actively connected over SSH.
```
ssh -i ~/.ssh/HOLMES.pem ubuntu@ami.public.ip
screen
cd ~/HOLMES/holmes_spartan; ./run-tests.sh
```

## On the local machine (not recommended)

Prerequisite: Your local machine should have over 72GB of memory to run these benchmarks.

1. [10 minutes] Ensure that the prerequisites are built.

Install and update [rustup](https://rustup.rs/)
```
rustup update
rustup install nightly
```

Clone the repository
```
git clone https://github.com/holmes-inputcheck/holmes-spartan.git
cd holmes-spartan
```

2. [3 hr] Run the benchmarks and extrapolation scripts

```
cargo +nightly build --release
./target/release/range_nizk [30 minutes]
./target/release/range_snark [1 hr]
./target/release/chisquare_nizk && python3 jl_nizk_extrapolate.py [30 minutes]
./target/release/chisquare_snark && python3 jl_snark_extrapolate.py [1 hr]
```

3. [1 minute] Interpret the results

For the NIZK range check numbers:
```
cat range_check_100000_nizk.txt
cat range_check_200000_nizk.txt
cat range_check_500000_nizk.txt
```

For the SNARK range check numbers:
```
cat range_check_100000_snark.txt
```

For the NIZK ZK-friendly sketching numbers:
```
cat jl_100000_nizk.txt
cat jl_200000_nizk.txt
cat jl_500000_nizk.txt
```

For the SNARK ZK-friendly sketching numbers:
```
cat jl_100000_snark.txt
```
