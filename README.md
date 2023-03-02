## Setup for HOLMES Spartan benchmarking:

1. [10 minutes] Ensure that the prerequisites are built.

Install [rustup](https://rustup.rs/)
```
rustup install nightly
```

Clone the repository
```
git clone https://github.com/holmes-inputcheck/holmes-spartan.git
cd holmes-spartan
```

2. [~30 minutes to 1 hr] Run the benchmarks and extrapolation scripts

```
cargo +nightly build --release
./target/release/range_nizk
./target/release/range_snark
./target/release/chisquare_nizk && jl_nizk_extrapolate.py
./target/release/chisquare_snark && jl_snark_extrapolate.py
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
cat range_check_100000_nizk.txt
```

For the NIZK ZK-friendly sketching numbers:
```
cat jl_100000_snark.txt
cat jl_200000_snark.txt
cat jl_500000_snark.txt
```

For the SNARK ZK-friendly sketching numbers:
```
cat jl_100000_snark.txt
```
