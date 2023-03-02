## Setup for HOLMES Spartan benchmarking:

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

2. [2 hr] Run the benchmarks and extrapolation scripts

```
cargo +nightly build --release
./target/release/range_nizk [30 minutes]
./target/release/range_snark [1 hr]
./target/release/chisquare_nizk && python3 jl_nizk_extrapolate.py
./target/release/chisquare_snark && python3 jl_snark_extrapolate.py
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
