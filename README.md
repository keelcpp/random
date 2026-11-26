# keel::random

Deterministic, cross-platform pseudo-random number generators, probability distributions, and OS cryptographic entropy for the [keel](https://github.com/keelcpp/keel) C++20 ecosystem — zero `<random>` or `<cmath>` in public headers, identical output across GCC, Clang, and MSVC.

## Features

- **OS Cryptographic Entropy**: `os_random_bytes`, `os_random_u64`, `os_random_u32` (`BCryptGenRandom` on Windows, `arc4random_buf` on Apple/BSD, `getrandom` with `/dev/urandom` fallback on Linux/POSIX).
- **Deterministic PRNGs**:
  - `SplitMix64` — fast 64-bit state mixer & seeder.
  - `Xoshiro256PlusPlus` (`DefaultRng`) — 256-bit state, `jump()` ($2^{128}$) and `long_jump()` ($2^{192}$) for parallel streams.
  - `Pcg32` — compact 16-byte PCG-XSH-RR generator with independent stream IDs.
  - `Mt19937` — canonical Matsumoto-Nishimura 1998 32-bit Mersenne Twister (`seed`, `seed_array`, `next_f64`, `next_f64_open`, `get_state`/`set_state`).
- **Cross-Platform Distributions** (bit-reproducible across libstdc++, libc++, and MSVC STL, generic over any generator with `next_u64()`, `next_u32()`, or `operator()()`):
  - Uniform: `uniform_f64`, `uniform_f64_open`, `uniform_f32`, `uniform_u64_bound` (Lemire unbiased), `uniform_u64`, `uniform_i64`, `uniform_usize`, `bernoulli`.
  - Continuous: `normal_f64` (256-layer Marsaglia-Tsang Ziggurat), `normal_f32`, `lognormal_f64`, `exponential_f64`, `gamma_f64` (Marsaglia-Tsang + Ahrens-Dieter), `beta_f64`, `chi_squared_f64`, `student_t_f64`, `weibull_f64`.
  - Discrete & Combinatorial: `poisson_u64` (Knuth + Hörmann PTRS), `binomial_u64` (BINV + BTPE), `geometric_u64`, `discrete_index`, `shuffle`, `sample_indices`.

## Build & Test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
python tests/verify_reference.py build/Release/test_random.exe
```

`tests/verify_reference.py` validates PRNG bitstreams against NumPy (`MT19937`) and canonical reference implementations (`SplitMix64`, `Xoshiro256++` including `jump`/`long_jump`, `PCG32`), and cross-checks all continuous and discrete distributions via SciPy (`scipy.stats`) Kolmogorov-Smirnov and Pearson chi-squared goodness-of-fit tests.
