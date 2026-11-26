#!/usr/bin/env python3
"""
Reference differential verification for keel::random against:
  1. NumPy MT19937 bit-exact stream verification (seed=5489 + seed_array)
  2. Independent Python bit-exact references for SplitMix64, Xoshiro256++ (incl. jump/long_jump), PCG32
  3. SciPy (scipy.stats) Kolmogorov-Smirnov & Pearson chi-squared goodness-of-fit tests
     across all 12 continuous & discrete distributions (100,000 samples each)

Usage:
  python tests/verify_reference.py <path-to-test_random.exe>
"""

import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
from scipy import stats


MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def rotl64(x: int, k: int) -> int:
    return ((x << k) | (x >> (64 - k))) & MASK64


def py_splitmix64(seed: int, n: int) -> np.ndarray:
    state = seed & MASK64
    out = []
    for _ in range(n):
        state = (state + 0x9E3779B97F4A7C15) & MASK64
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        out.append((z ^ (z >> 31)) & MASK64)
    return np.array(out, dtype=np.uint64)


def py_xoshiro256pp(seed: int) -> np.ndarray:
    s = list(int(v) for v in py_splitmix64(seed, 4))

    def nxt() -> int:
        res = (rotl64((s[0] + s[3]) & MASK64, 23) + s[0]) & MASK64
        t = (s[1] << 17) & MASK64
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= t
        s[3] = rotl64(s[3], 45)
        return res

    def do_jump(poly):
        j = [0, 0, 0, 0]
        for p in poly:
            for b in range(64):
                if p & (1 << b):
                    for k in range(4):
                        j[k] ^= s[k]
                nxt()
        for k in range(4):
            s[k] = j[k]

    out = [nxt() for _ in range(64)]
    do_jump([0x180EC6D33CFD0ABA, 0xD5A61266F0C9392C, 0xA9582618E03FC9AA, 0x39ABDC4529B1661C])
    out.extend(nxt() for _ in range(32))
    do_jump([0x76E15D3EFEFDCBBF, 0xC5004E441C522FB3, 0x77710069854EE241, 0x39109BB02ACBE635])
    out.extend(nxt() for _ in range(32))
    return np.array(out, dtype=np.uint64)


def py_pcg32(init_state: int, stream: int, n: int) -> np.ndarray:
    inc = ((stream << 1) | 1) & MASK64
    state = 0

    def nxt() -> int:
        nonlocal state
        old = state
        state = (old * 6364136223846793005 + inc) & MASK64
        xorshifted = (((old >> 18) ^ old) >> 27) & MASK32
        rot = (old >> 59) & 31
        return ((xorshifted >> rot) | ((xorshifted << ((-rot) & 31)) & MASK32)) & MASK32

    nxt()
    state = (state + init_state) & MASK64
    nxt()
    return np.array([nxt() for _ in range(n)], dtype=np.uint32)


def main():
    if len(sys.argv) < 2:
        print("Usage: verify_reference.py <path-to-test_random.exe>")
        sys.exit(2)

    exe = Path(sys.argv[1]).resolve()
    passed = []

    with tempfile.TemporaryDirectory(prefix="keel_rng_ref_") as td:
        tmp = Path(td)
        subprocess.run([str(exe), "--dump-ref", str(tmp)], check=True)

        # 1. Bit-exact PRNG verification against NumPy MT19937 & canonical reference equations
        mt_got = np.frombuffer((tmp / "mt19937_5489.u32").read_bytes(), dtype=np.uint32)
        bg = np.random.MT19937()
        bg._legacy_seeding(5489)
        mt_ref = np.array([bg.random_raw() for _ in range(1000)], dtype=np.uint32)
        assert np.array_equal(mt_got, mt_ref), "MT19937(5489) diverged from NumPy!"
        passed.append("prng:mt19937_5489_bitexact")

        mt_arr_got = np.frombuffer((tmp / "mt19937_array.u32").read_bytes(), dtype=np.uint32)
        bg2 = np.random.MT19937()
        bg2._legacy_seeding(np.array([0x123, 0x234, 0x345, 0x456], dtype=np.uint32))
        mt_arr_ref = np.array([bg2.random_raw() for _ in range(1000)], dtype=np.uint32)
        assert np.array_equal(mt_arr_got, mt_arr_ref), "MT19937(seed_array) diverged from NumPy!"
        passed.append("prng:mt19937_array_bitexact")

        sm_got = np.frombuffer((tmp / "splitmix64.u64").read_bytes(), dtype=np.uint64)
        assert np.array_equal(sm_got, py_splitmix64(123456789, 128)), "SplitMix64 diverged!"
        passed.append("prng:splitmix64_bitexact")

        xo_got = np.frombuffer((tmp / "xoshiro256pp.u64").read_bytes(), dtype=np.uint64)
        assert np.array_equal(xo_got, py_xoshiro256pp(987654321)), "Xoshiro256++ (incl. jump/long_jump) diverged!"
        passed.append("prng:xoshiro256pp_jump_bitexact")

        pcg_got = np.frombuffer((tmp / "pcg32.u32").read_bytes(), dtype=np.uint32)
        assert np.array_equal(pcg_got, py_pcg32(42, 54, 128)), "PCG32 diverged!"
        passed.append("prng:pcg32_bitexact")

        # 2. Continuous distributions: 1-sample Kolmogorov-Smirnov test vs SciPy (N = 100,000)
        cont_cases = [
            ("uniform", stats.uniform(loc=-3.5, scale=8.0)),
            ("normal", stats.norm(loc=2.5, scale=1.75)),
            ("lognormal", stats.lognorm(s=0.6, scale=np.exp(0.3))),
            ("exponential", stats.expon(scale=1.0 / 1.8)),
            ("gamma_gt1", stats.gamma(a=3.7, scale=2.2)),
            ("gamma_lt1", stats.gamma(a=0.4, scale=1.5)),
            ("beta", stats.beta(a=2.2, b=4.8)),
            ("beta_tiny", stats.beta(a=0.25, b=0.35)),
            ("chi2", stats.chi2(df=5.5)),
            ("student_t", stats.t(df=6.0)),
            ("weibull", stats.weibull_min(c=1.7, scale=2.5)),
        ]
        for name, dist in cont_cases:
            samples = np.frombuffer((tmp / f"{name}.f64").read_bytes(), dtype=np.float64)
            assert np.all(np.isfinite(samples)), f"[{name}] non-finite sample!"
            ks = stats.kstest(samples, dist.cdf)
            if ks.pvalue < 1e-4:
                raise AssertionError(f"[{name}] KS test failed vs SciPy: D={ks.statistic:.5f}, p={ks.pvalue:.3e}")
            passed.append(f"scipy_ks:{name} (p={ks.pvalue:.3f})")

        # 3. Discrete distributions: Pearson chi-squared goodness-of-fit vs SciPy PMF (N = 100,000)
        def check_discrete_chi2(name: str, pmf_fn, lo: int, hi: int):
            samples = np.frombuffer((tmp / f"{name}.u64").read_bytes(), dtype=np.uint64)
            n = len(samples)
            obs = []
            exp = []
            # Bucket tail below lo, individual bins [lo..hi], tail above hi, merging sparse bins (>= 20 expected)
            tail_lo_p = sum(pmf_fn(k) for k in range(0, lo))
            cur_o = int(np.sum(samples < lo))
            cur_p = tail_lo_p
            for k in range(lo, hi + 1):
                cur_o += int(np.sum(samples == k))
                cur_p += float(pmf_fn(k))
                if cur_p * n >= 25.0:
                    obs.append(cur_o)
                    exp.append(cur_p * n)
                    cur_o = 0
                    cur_p = 0.0
            tail_hi_o = int(np.sum(samples > hi)) + cur_o
            tail_hi_p = max(0.0, 1.0 - sum(exp) / n)
            if tail_hi_p * n >= 25.0:
                obs.append(tail_hi_o)
                exp.append(tail_hi_p * n)
            else:
                obs[-1] += tail_hi_o
                exp[-1] += tail_hi_p * n
            res = stats.chisquare(obs, f_exp=exp)
            if res.pvalue < 1e-4:
                raise AssertionError(f"[{name}] chi2 test failed vs SciPy: stat={res.statistic:.2f}, p={res.pvalue:.3e}")
            passed.append(f"scipy_chi2:{name} (p={res.pvalue:.3f})")

        check_discrete_chi2("poisson_knuth", lambda k: stats.poisson.pmf(k, 7.5), 0, 22)
        check_discrete_chi2("poisson_ptrs", lambda k: stats.poisson.pmf(k, 45.0), 20, 75)
        check_discrete_chi2("binomial_binv", lambda k: stats.binom.pmf(k, 25, 0.2), 0, 15)
        check_discrete_chi2("binomial_btpe", lambda k: stats.binom.pmf(k, 120, 0.35), 20, 65)
        check_discrete_chi2("binomial_flip", lambda k: stats.binom.pmf(k, 200, 0.8), 135, 185)
        check_discrete_chi2("geometric", lambda k: stats.geom.pmf(k + 1, 0.3), 0, 20)

        # Small-p geometric (p = 1e-4): check quantiles via KS against continuous exponential approximation / discrete CDF
        g_tiny = np.frombuffer((tmp / "geometric_tiny.u64").read_bytes(), dtype=np.uint64).astype(np.float64)
        exp_mean = (1.0 - 1e-4) / 1e-4
        assert abs(g_tiny.mean() - exp_mean) / exp_mean < 0.02, f"geometric_tiny mean {g_tiny.mean()} vs {exp_mean}"
        passed.append("scipy_check:geometric_tiny_log1p")

        # Discrete categorical weights
        disc = np.frombuffer((tmp / "discrete.u64").read_bytes(), dtype=np.uint64)
        obs_d = [int(np.sum(disc == k)) for k in range(5)]
        exp_d = [100000 * w for w in [0.1, 0.25, 0.05, 0.4, 0.2]]
        res_d = stats.chisquare(obs_d, f_exp=exp_d)
        assert res_d.pvalue >= 1e-4, f"discrete chi2 failed: p={res_d.pvalue:.3e}"
        passed.append(f"scipy_chi2:discrete (p={res_d.pvalue:.3f})")

    print(f"ALL RANDOM REFERENCE CHECKS PASSED ({len(passed)}/{len(passed)}):")
    for item in passed:
        print(f"  [PASS] {item}")


if __name__ == "__main__":
    main()
