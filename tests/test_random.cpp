#include "keel/format.h"
#include "keel/math.h"
#include "keel/random.h"

using namespace keel::random;

namespace {

keel::i32 g_failures = 0;

void check(bool cond, const char* expr, keel::i32 line) {
    if (!cond) {
        keel::eprintln("FAIL [line %d]: %s", line, expr);
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __LINE__)

struct SampleStats {
    keel::f64 mean = 0.0;
    keel::f64 variance = 0.0;
    keel::f64 min_val = 0.0;
    keel::f64 max_val = 0.0;
};

template <typename Fn>
SampleStats collect_stats(keel::usize n, Fn&& fn) {
    keel::f64 mean = 0.0;
    keel::f64 m2 = 0.0;
    keel::f64 lo = 1e300;
    keel::f64 hi = -1e300;
    for (keel::usize i = 1; i <= n; ++i) {
        const keel::f64 x = keel::as<keel::f64>(fn());
        if (x < lo) lo = x;
        if (x > hi) hi = x;
        const keel::f64 delta = x - mean;
        mean += delta / keel::as<keel::f64>(i);
        m2 += delta * (x - mean);
    }
    return SampleStats{mean, m2 / keel::as<keel::f64>(n - 1), lo, hi};
}

void test_os_random() {
    keel::u8 empty[1] = {0xAA};
    CHECK(keel::random::os_random_bytes(keel::MutArrayRef<keel::u8>(empty, 0)).is_ok());
    CHECK(empty[0] == 0xAA);

    keel::u8 buf1[32] = {};
    keel::u8 buf2[32] = {};
    CHECK(keel::random::os_random_bytes(keel::MutArrayRef<keel::u8>(buf1, 32)).is_ok());
    CHECK(keel::random::os_random_bytes(keel::MutArrayRef<keel::u8>(buf2, 32)).is_ok());

    bool differs = false;
    bool any_nonzero = false;
    for (keel::usize i = 0; i < 32; ++i) {
        if (buf1[i] != buf2[i]) differs = true;
        if (buf1[i] != 0) any_nonzero = true;
    }
    CHECK(differs);
    CHECK(any_nonzero);

    auto r64_a = keel::random::os_random_u64();
    auto r64_b = keel::random::os_random_u64();
    CHECK(r64_a.is_ok() && r64_b.is_ok());
    CHECK(r64_a.value() != r64_b.value());

    auto r32 = keel::random::os_random_u32();
    CHECK(r32.is_ok());

    auto rng_res = keel::random::Xoshiro256PlusPlus::from_os();
    CHECK(rng_res.is_ok());
}

void test_prng_determinism() {
    // Constexpr check on SplitMix64 & Xoshiro256PlusPlus & Pcg32.
    constexpr keel::u64 c_sm = []() {
        keel::random::SplitMix64 sm(42ULL);
        return sm.next_u64();
    }();
    CHECK(c_sm != 0ULL);

    constexpr keel::u64 c_xo = []() {
        keel::random::Xoshiro256PlusPlus xo(12345ULL);
        return xo.next_u64();
    }();
    keel::random::Xoshiro256PlusPlus xo1(12345ULL);
    keel::random::Xoshiro256PlusPlus xo2(12345ULL);
    CHECK(xo1.next_u64() == c_xo);
    CHECK(xo2.next_u64() == c_xo);

    // Zero-state guard.
    keel::random::Xoshiro256PlusPlus xo_zero(0, 0, 0, 0);
    CHECK(xo_zero.next_u64() != 0ULL);

    // Jump produces distinct streams.
    keel::random::Xoshiro256PlusPlus j1(777ULL);
    keel::random::Xoshiro256PlusPlus j2 = j1;
    j2.jump();
    keel::random::Xoshiro256PlusPlus j3 = j1;
    j3.long_jump();
    const keel::u64 v1 = j1.next_u64();
    const keel::u64 v2 = j2.next_u64();
    const keel::u64 v3 = j3.next_u64();
    CHECK(v1 != v2 && v2 != v3 && v1 != v3);

    // PCG32 distinct streams.
    keel::random::Pcg32 p1(42ULL, 1ULL);
    keel::random::Pcg32 p2(42ULL, 1ULL);
    keel::random::Pcg32 p3(42ULL, 2ULL);
    CHECK(p1.next_u32() == p2.next_u32());
    CHECK(p1.next_u32() != p3.next_u32());
}

void test_mt19937_vectors() {
    // Canonical C++11 [rand.predef] requirement: 10000th draw of mt19937(5489) == 4123659995.
    keel::random::Mt19937 mt(5489u);
    keel::u32 first = mt.next_u32();
    CHECK(first == 3499211612u);
    keel::u32 ten_thousandth = first;
    for (keel::usize i = 1; i < 10000; ++i) {
        ten_thousandth = mt.next_u32();
    }
    CHECK(ten_thousandth == 4123659995u);

    // Canonical seed(5489): first 53-bit uniform == 0.8147236863931789.
    mt.seed(5489u);
    const keel::f64 u0 = mt.next_f64_open();
    CHECK(keel::abs(u0 - 0.8147236863931789) < 1e-15);

    // Reference mt19937ar.c init_by_array({0x123, 0x234, 0x345, 0x456}) vector.
    const keel::u32 init_keys[4] = {0x123u, 0x234u, 0x345u, 0x456u};
    mt.seed_array(keel::ArrayRef<keel::u32>(init_keys, 4));
    CHECK(mt.next_u32() == 1067595299u);
    CHECK(mt.next_u32() == 955945823u);
    CHECK(mt.next_u32() == 477289528u);

    // State save & restore round-trip.
    keel::u32 state[keel::random::Mt19937::kStateSize] = {};
    keel::usize idx = 0;
    mt.get_state(keel::MutArrayRef<keel::u32>(state, keel::random::Mt19937::kStateSize), idx);
    const keel::u32 next_a = mt.next_u32();
    const keel::f64 next_f = mt.next_f64_open();

    keel::random::Mt19937 mt_restored;
    mt_restored.set_state(keel::ArrayRef<keel::u32>(state, keel::random::Mt19937::kStateSize), idx);
    CHECK(mt_restored.next_u32() == next_a);
    CHECK(mt_restored.next_f64_open() == next_f);

    // All-zero state guard: never stays stuck at 0.
    keel::u32 zeros[keel::random::Mt19937::kStateSize] = {};
    mt_restored.set_state(keel::ArrayRef<keel::u32>(zeros, keel::random::Mt19937::kStateSize), 0);
    bool nonzero = false;
    for (keel::usize i = 0; i < 16; ++i) {
        if (mt_restored.next_u32() != 0u) nonzero = true;
    }
    CHECK(nonzero);
}

struct MinimalUrbg32 {
    keel::u32 s = 0x12345678u;
    keel::u32 operator()() noexcept {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        return s;
    }
};

void test_minimal_urbg_interop() {
    MinimalUrbg32 g;
    const keel::f64 u = keel::random::uniform_f64(g);
    CHECK(u >= 0.0 && u < 1.0);
    const keel::f64 z = keel::random::normal_f64(g);
    CHECK(keel::is_finite(z));
    const keel::u64 b = keel::random::uniform_u64_bound(g, 100);
    CHECK(b < 100);
}

void test_uniform_distributions() {
    keel::random::DefaultRng rng(20261120ULL);
    constexpr keel::usize kN = 100000;

    auto s_f64 = collect_stats(kN, [&]() { return keel::random::uniform_f64(rng, -2.0, 6.0); });
    CHECK(s_f64.min_val >= -2.0 && s_f64.max_val < 6.0);
    CHECK(keel::abs(s_f64.mean - 2.0) < 0.03);
    CHECK(keel::abs(s_f64.variance - (64.0 / 12.0)) < 0.08);

    for (keel::usize i = 0; i < 10000; ++i) {
        const keel::f64 uo = keel::random::uniform_f64_open(rng);
        CHECK(uo > 0.0 && uo < 1.0);
    }

    auto s_f32 = collect_stats(kN, [&]() { return keel::random::uniform_f32(rng, 1.0f, 3.0f); });
    CHECK(s_f32.min_val >= 1.0 && s_f32.max_val < 3.0);
    CHECK(keel::abs(s_f32.mean - 2.0) < 0.02);

    // Lemire unbiased integer bounds & inclusive ranges.
    keel::u64 counts[7] = {};
    for (keel::usize i = 0; i < 70000; ++i) {
        const keel::u64 v = keel::random::uniform_u64_bound(rng, 7);
        CHECK(v < 7);
        ++counts[v];
    }
    for (keel::usize b = 0; b < 7; ++b) {
        CHECK(counts[b] > 9400 && counts[b] < 10600);
    }

    auto s_i64 = collect_stats(kN, [&]() { return keel::random::uniform_i64(rng, -5, 5); });
    CHECK(s_i64.min_val == -5.0 && s_i64.max_val == 5.0);
    CHECK(keel::abs(s_i64.mean - 0.0) < 0.04);
    CHECK(keel::abs(s_i64.variance - 10.0) < 0.15);

    CHECK(keel::random::uniform_u64_bound(rng, 0) == 0);
    CHECK(keel::random::uniform_u64_bound(rng, 1) == 0);
    CHECK(keel::random::uniform_i64(rng, 9, 4) == 9);
    CHECK(keel::random::uniform_usize(rng, 3, 3) == 3);

    auto s_bern = collect_stats(kN, [&]() { return keel::random::bernoulli(rng, 0.3) ? 1.0 : 0.0; });
    CHECK(keel::abs(s_bern.mean - 0.3) < 0.01);
    CHECK(!keel::random::bernoulli(rng, 0.0));
    CHECK(keel::random::bernoulli(rng, 1.0));
}

void test_continuous_distributions() {
    keel::random::DefaultRng rng(987654321ULL);
    constexpr keel::usize kN = 100000;

    // Normal N(3, 2^2).
    auto s_norm = collect_stats(kN, [&]() { return keel::random::normal_f64(rng, 3.0, 2.0); });
    CHECK(keel::abs(s_norm.mean - 3.0) < 0.03);
    CHECK(keel::abs(s_norm.variance - 4.0) < 0.08);

    // Normal f32.
    auto s_norm32 = collect_stats(20000, [&]() { return keel::random::normal_f32(rng, -1.0f, 0.5f); });
    CHECK(keel::abs(s_norm32.mean + 1.0) < 0.03);
    CHECK(keel::abs(s_norm32.variance - 0.25) < 0.02);

    // Lognormal(0.5, 0.4): mean = exp(0.5 + 0.08) = exp(0.58).
    auto s_ln = collect_stats(kN, [&]() { return keel::random::lognormal_f64(rng, 0.5, 0.4); });
    const keel::f64 ln_mean = keel::exp(0.5 + 0.5 * 0.16);
    CHECK(s_ln.min_val > 0.0);
    CHECK(keel::abs(s_ln.mean - ln_mean) < 0.02);

    // Exponential(rate = 2.5): mean = 0.4, var = 0.16.
    auto s_exp = collect_stats(kN, [&]() { return keel::random::exponential_f64(rng, 2.5); });
    CHECK(s_exp.min_val > 0.0);
    CHECK(keel::abs(s_exp.mean - 0.4) < 0.01);
    CHECK(keel::abs(s_exp.variance - 0.16) < 0.01);

    // Gamma(shape = 4.5, scale = 2.0): mean = 9.0, var = 18.0.
    auto s_gam1 = collect_stats(kN, [&]() { return keel::random::gamma_f64(rng, 4.5, 2.0); });
    CHECK(s_gam1.min_val > 0.0);
    CHECK(keel::abs(s_gam1.mean - 9.0) < 0.08);
    CHECK(keel::abs(s_gam1.variance - 18.0) < 0.4);

    // Gamma(shape = 0.35, scale = 3.0) (Ahrens-Dieter boost): mean = 1.05, var = 3.15.
    auto s_gam2 = collect_stats(kN, [&]() { return keel::random::gamma_f64(rng, 0.35, 3.0); });
    CHECK(s_gam2.min_val > 0.0);
    CHECK(keel::abs(s_gam2.mean - 1.05) < 0.04);
    CHECK(keel::abs(s_gam2.variance - 3.15) < 0.2);

    // Beta(2.5, 5.0): mean = 1/3, var = (2.5*5.0) / (7.5^2 * 8.5) = 0.02614379...
    auto s_beta = collect_stats(kN, [&]() { return keel::random::beta_f64(rng, 2.5, 5.0); });
    CHECK(s_beta.min_val >= 0.0 && s_beta.max_val <= 1.0);
    CHECK(keel::abs(s_beta.mean - (2.5 / 7.5)) < 0.005);
    CHECK(keel::abs(s_beta.variance - 0.02614379) < 0.0015);

    // Tiny Beta(0.01, 0.01) underflow guard.
    for (keel::usize i = 0; i < 1000; ++i) {
        const keel::f64 b = keel::random::beta_f64(rng, 0.01, 0.01);
        CHECK(keel::is_finite(b) && b >= 0.0 && b <= 1.0);
    }

    // Chi-squared(df = 7): mean = 7, var = 14.
    auto s_chi2 = collect_stats(kN, [&]() { return keel::random::chi_squared_f64(rng, 7.0); });
    CHECK(keel::abs(s_chi2.mean - 7.0) < 0.06);
    CHECK(keel::abs(s_chi2.variance - 14.0) < 0.35);

    // Student-t(df = 10): mean = 0, var = 10 / 8 = 1.25.
    auto s_t = collect_stats(kN, [&]() { return keel::random::student_t_f64(rng, 10.0); });
    CHECK(keel::abs(s_t.mean) < 0.02);
    CHECK(keel::abs(s_t.variance - 1.25) < 0.05);

    // Weibull(shape = 2.0, scale = 3.0) (Rayleigh): mean = 3*sqrt(pi)/2 = 2.65868, var = 9*(1 - pi/4) = 1.93142.
    auto s_wbl = collect_stats(kN, [&]() { return keel::random::weibull_f64(rng, 2.0, 3.0); });
    CHECK(s_wbl.min_val > 0.0);
    CHECK(keel::abs(s_wbl.mean - 2.658680776) < 0.025);
    CHECK(keel::abs(s_wbl.variance - 1.931416597) < 0.05);
}

void test_discrete_and_combinatorial() {
    keel::random::DefaultRng rng(135792468ULL);
    constexpr keel::usize kN = 100000;

    // Poisson edge cases + Knuth + PTRS.
    CHECK(keel::random::poisson_u64(rng, 0.0) == 0ULL);
    CHECK(keel::random::poisson_u64(rng, -5.0) == 0ULL);

    auto s_p1 = collect_stats(kN, [&]() { return keel::random::poisson_u64(rng, 4.5); });
    CHECK(keel::abs(s_p1.mean - 4.5) < 0.04);
    CHECK(keel::abs(s_p1.variance - 4.5) < 0.1);

    auto s_p2 = collect_stats(kN, [&]() { return keel::random::poisson_u64(rng, 50.0); });
    CHECK(keel::abs(s_p2.mean - 50.0) < 0.15);
    CHECK(keel::abs(s_p2.variance - 50.0) < 1.0);

    auto s_p3 = collect_stats(50000, [&]() { return keel::random::poisson_u64(rng, 500.0); });
    CHECK(keel::abs(s_p3.mean - 500.0) < 0.5);
    CHECK(keel::abs(s_p3.variance - 500.0) < 15.0);

    // Binomial edges + BINV + BTPE + flipped BTPE.
    CHECK(keel::random::binomial_u64(rng, 0, 0.5) == 0ULL);
    CHECK(keel::random::binomial_u64(rng, 50, 0.0) == 0ULL);
    CHECK(keel::random::binomial_u64(rng, 50, 1.0) == 50ULL);

    auto s_b1 = collect_stats(kN, [&]() { return keel::random::binomial_u64(rng, 20, 0.25); }); // BINV: mean=5, var=3.75
    CHECK(s_b1.max_val <= 20.0);
    CHECK(keel::abs(s_b1.mean - 5.0) < 0.04);
    CHECK(keel::abs(s_b1.variance - 3.75) < 0.09);

    auto s_b2 = collect_stats(kN, [&]() { return keel::random::binomial_u64(rng, 100, 0.3); }); // BTPE: mean=30, var=21
    CHECK(s_b2.max_val <= 100.0);
    CHECK(keel::abs(s_b2.mean - 30.0) < 0.08);
    CHECK(keel::abs(s_b2.variance - 21.0) < 0.5);

    auto s_b3 = collect_stats(kN, [&]() { return keel::random::binomial_u64(rng, 1000, 0.73); }); // Flipped BTPE: mean=730, var=197.1
    CHECK(s_b3.max_val <= 1000.0);
    CHECK(keel::abs(s_b3.mean - 730.0) < 0.25);
    CHECK(keel::abs(s_b3.variance - 197.1) < 5.0);

    // Geometric(p = 0.25): 0-based failures, mean = (1-p)/p = 3.0, var = (1-p)/p^2 = 12.0.
    CHECK(keel::random::geometric_u64(rng, 1.0) == 0ULL);
    auto s_geo = collect_stats(kN, [&]() { return keel::random::geometric_u64(rng, 0.25); });
    CHECK(keel::abs(s_geo.mean - 3.0) < 0.06);
    CHECK(keel::abs(s_geo.variance - 12.0) < 0.4);

    // Discrete index.
    const keel::f64 weights[4] = {1.0, 2.0, 3.0, 4.0};
    keel::u64 hist[4] = {};
    for (keel::usize i = 0; i < 100000; ++i) {
        const keel::usize idx = keel::random::discrete_index(rng, keel::ArrayRef<keel::f64>(weights, 4));
        CHECK(idx < 4);
        ++hist[idx];
    }
    CHECK(keel::abs(keel::as<keel::f64>(hist[0]) / 100000.0 - 0.1) < 0.005);
    CHECK(keel::abs(keel::as<keel::f64>(hist[1]) / 100000.0 - 0.2) < 0.005);
    CHECK(keel::abs(keel::as<keel::f64>(hist[2]) / 100000.0 - 0.3) < 0.005);
    CHECK(keel::abs(keel::as<keel::f64>(hist[3]) / 100000.0 - 0.4) < 0.005);

    // Shuffle preserves all elements and distributes uniformly.
    keel::u64 pos0[5] = {};
    for (keel::usize trial = 0; trial < 50000; ++trial) {
        keel::u32 arr[5] = {0, 1, 2, 3, 4};
        keel::random::shuffle(rng, keel::MutArrayRef<keel::u32>(arr, 5));
        keel::u32 mask = 0;
        for (keel::usize i = 0; i < 5; ++i) mask |= (1u << arr[i]);
        CHECK(mask == 31u);
        ++pos0[arr[0]];
    }
    for (keel::usize v = 0; v < 5; ++v) {
        CHECK(pos0[v] > 9400 && pos0[v] < 10600);
    }

    // sample_indices: k=4 from n=10, distinct & uniform.
    keel::u64 freq[10] = {};
    for (keel::usize trial = 0; trial < 50000; ++trial) {
        keel::usize out[4] = {};
        const keel::usize got = keel::random::sample_indices(rng, 10, keel::MutArrayRef<keel::usize>(out, 4));
        CHECK(got == 4);
        keel::u32 seen = 0;
        for (keel::usize i = 0; i < 4; ++i) {
            CHECK(out[i] < 10);
            CHECK((seen & (1u << out[i])) == 0u);
            seen |= (1u << out[i]);
            ++freq[out[i]];
        }
    }
    for (keel::usize i = 0; i < 10; ++i) {
        CHECK(freq[i] > 19000 && freq[i] < 21000);
    }
}

} // namespace

int main() {
    test_os_random();
    test_prng_determinism();
    test_mt19937_vectors();
    test_minimal_urbg_interop();
    test_uniform_distributions();
    test_continuous_distributions();
    test_discrete_and_combinatorial();

    if (g_failures == 0) {
        keel::println("All keel::random tests passed.");
        return 0;
    }
    keel::eprintln("%d test failure(s).", g_failures);
    return 1;
}
