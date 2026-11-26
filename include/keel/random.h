#pragma once

#include "keel/bits.h"
#include "keel/core.h"
#include "keel/error.h"
#include "keel/math.h"
#include "keel/ref.h"
#include "keel/result.h"

namespace keel::random {

// ============================================================================
// 1. OS Cryptographic Entropy
// ============================================================================

/// Fill `out` with cryptographically strong random bytes from the OS CSPRNG
/// (BCryptGenRandom on Windows, arc4random_buf on Apple/BSD, getrandom with
/// /dev/urandom fallback on Linux/POSIX).
[[nodiscard]] Error os_random_bytes(MutArrayRef<u8> out) noexcept;

/// Draw a cryptographically strong 64-bit unsigned integer from the OS CSPRNG.
[[nodiscard]] Result<u64, Error> os_random_u64() noexcept;

/// Draw a cryptographically strong 32-bit unsigned integer from the OS CSPRNG.
[[nodiscard]] Result<u32, Error> os_random_u32() noexcept;

// ============================================================================
// 2. Deterministic Pseudo-Random Number Generators
// ============================================================================

/// SplitMix64: fast 64-bit state mixer and PRNG seeder.
struct SplitMix64 {
    u64 state = 0x9e3779b97f4a7c15ULL;

    constexpr SplitMix64() noexcept = default;
    constexpr explicit SplitMix64(u64 s) noexcept : state(s) {}

    constexpr void seed(u64 s) noexcept { state = s; }

    [[nodiscard]] constexpr u64 next_u64() noexcept {
        u64 z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }

    [[nodiscard]] constexpr u32 next_u32() noexcept { return as<u32>(next_u64() >> 32); }

    [[nodiscard]] constexpr f64 next_f64() noexcept {
        return as<f64>(next_u64() >> 11) * (1.0 / 9007199254740992.0);
    }

    [[nodiscard]] constexpr f32 next_f32() noexcept {
        return as<f32>(next_u32() >> 8) * (1.0f / 16777216.0f);
    }

    [[nodiscard]] constexpr u64 operator()() noexcept { return next_u64(); }
};

/// xoshiro256++: fast, high-quality 64-bit general-purpose PRNG with 256-bit
/// state and exact jump functions for independent parallel streams.
struct Xoshiro256PlusPlus {
    u64 s[4] = {};

    constexpr Xoshiro256PlusPlus() noexcept { seed(0x9e3779b97f4a7c15ULL); }
    constexpr explicit Xoshiro256PlusPlus(u64 init_seed) noexcept { seed(init_seed); }

    constexpr Xoshiro256PlusPlus(u64 s0, u64 s1, u64 s2, u64 s3) noexcept {
        if ((s0 | s1 | s2 | s3) == 0ULL) {
            seed(0ULL);
        } else {
            s[0] = s0;
            s[1] = s1;
            s[2] = s2;
            s[3] = s3;
        }
    }

    constexpr void seed(u64 init_seed) noexcept {
        SplitMix64 sm(init_seed);
        s[0] = sm.next_u64();
        s[1] = sm.next_u64();
        s[2] = sm.next_u64();
        s[3] = sm.next_u64();
        if ((s[0] | s[1] | s[2] | s[3]) == 0ULL) {
            s[0] = 0x9e3779b97f4a7c15ULL;
        }
    }

    [[nodiscard]] static Result<Xoshiro256PlusPlus> from_os() noexcept {
        u8 buf[32] = {};
        const Error err = os_random_bytes(MutArrayRef<u8>(buf, 32));
        if (err.is_err()) {
            return err;
        }
        auto load_u64 = [](const u8* p) noexcept -> u64 {
            return as<u64>(p[0]) | (as<u64>(p[1]) << 8) | (as<u64>(p[2]) << 16) |
                   (as<u64>(p[3]) << 24) | (as<u64>(p[4]) << 32) | (as<u64>(p[5]) << 40) |
                   (as<u64>(p[6]) << 48) | (as<u64>(p[7]) << 56);
        };
        return Xoshiro256PlusPlus(load_u64(buf + 0), load_u64(buf + 8), load_u64(buf + 16), load_u64(buf + 24));
    }

    [[nodiscard]] constexpr u64 next_u64() noexcept {
        const u64 result = rotl(s[0] + s[3], 23) + s[0];
        const u64 t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = rotl(s[3], 45);
        return result;
    }

    [[nodiscard]] constexpr u32 next_u32() noexcept { return as<u32>(next_u64() >> 32); }

    [[nodiscard]] constexpr f64 next_f64() noexcept {
        return as<f64>(next_u64() >> 11) * (1.0 / 9007199254740992.0);
    }

    [[nodiscard]] constexpr f32 next_f32() noexcept {
        return as<f32>(next_u32() >> 8) * (1.0f / 16777216.0f);
    }

    [[nodiscard]] constexpr u64 operator()() noexcept { return next_u64(); }

    /// Advance the generator state by 2^128 calls to next_u64().
    constexpr void jump() noexcept {
        constexpr u64 kJump[4] = {
            0x180ec6d33cfd0abaULL, 0xd5a61266f0c9392cULL, 0xa9582618e03fc9aaULL, 0x39abdc4529b1661cULL};
        apply_jump(kJump);
    }

    /// Advance the generator state by 2^192 calls to next_u64().
    constexpr void long_jump() noexcept {
        constexpr u64 kLongJump[4] = {
            0x76e15d3efefdcbbfULL, 0xc5004e441c522fb3ULL, 0x77710069854ee241ULL, 0x39109bb02acbe635ULL};
        apply_jump(kLongJump);
    }

private:
    constexpr void apply_jump(const u64 poly[4]) noexcept {
        u64 s0 = 0;
        u64 s1 = 0;
        u64 s2 = 0;
        u64 s3 = 0;
        for (usize i = 0; i < 4; ++i) {
            for (u32 b = 0; b < 64; ++b) {
                if ((poly[i] & (u64{1} << b)) != 0ULL) {
                    s0 ^= s[0];
                    s1 ^= s[1];
                    s2 ^= s[2];
                    s3 ^= s[3];
                }
                (void)next_u64();
            }
        }
        s[0] = s0;
        s[1] = s1;
        s[2] = s2;
        s[3] = s3;
    }
};

/// PCG32 (PCG-XSH-RR): compact 16-byte 32-bit generator with selectable streams.
struct Pcg32 {
    u64 state = 0;
    u64 inc = 0;

    constexpr explicit Pcg32(u64 init_state = 0x853c49e6748fea9bULL, u64 stream = 0xda3e39cb94b95bdbULL) noexcept {
        seed(init_state, stream);
    }

    constexpr void seed(u64 init_state, u64 stream = 0xda3e39cb94b95bdbULL) noexcept {
        state = 0ULL;
        inc = (stream << 1) | 1ULL;
        (void)next_u32();
        state += init_state;
        (void)next_u32();
    }

    [[nodiscard]] constexpr u32 next_u32() noexcept {
        const u64 oldstate = state;
        state = oldstate * 6364136223846793005ULL + inc;
        const u32 xorshifted = as<u32>(((oldstate >> 18) ^ oldstate) >> 27);
        const u32 rot = as<u32>(oldstate >> 59);
        return (xorshifted >> rot) | (xorshifted << ((0u - rot) & 31u));
    }

    [[nodiscard]] constexpr u64 next_u64() noexcept {
        const u64 hi = as<u64>(next_u32());
        const u64 lo = as<u64>(next_u32());
        return (hi << 32) | lo;
    }

    [[nodiscard]] constexpr f64 next_f64() noexcept {
        return as<f64>(next_u64() >> 11) * (1.0 / 9007199254740992.0);
    }

    [[nodiscard]] constexpr f32 next_f32() noexcept {
        return as<f32>(next_u32() >> 8) * (1.0f / 16777216.0f);
    }

    [[nodiscard]] constexpr u32 operator()() noexcept { return next_u32(); }
};

/// Canonical Matsumoto-Nishimura 1998 32-bit Mersenne Twister (MT19937).
/// Bit-identical to reference mt19937ar.c across all platforms and compilers.
struct Mt19937 {
    static constexpr usize kStateSize = 624;

    explicit Mt19937(u32 s = 5489u) noexcept;

    /// Seed with a single 32-bit integer (canonical init_genrand).
    void seed(u32 s) noexcept;

    /// Seed with an array of 32-bit keys (canonical init_by_array).
    void seed_array(ArrayRef<u32> key) noexcept;

    /// Draw next 32-bit unsigned word.
    [[nodiscard]] u32 next_u32() noexcept;

    /// Draw 64 bits from two consecutive 32-bit draws (high word first).
    [[nodiscard]] u64 next_u64() noexcept;

    /// 53-bit uniform double in [0, 1) (canonical genrand_res53).
    [[nodiscard]] f64 next_f64() noexcept;

    /// 53-bit uniform double in (0, 1) (strictly positive, skips 0.0).
    [[nodiscard]] f64 next_f64_open() noexcept;

    /// 24-bit uniform float in [0, 1).
    [[nodiscard]] f32 next_f32() noexcept;

    [[nodiscard]] u32 operator()() noexcept { return next_u32(); }

    /// Copy the internal 624-word state and cursor index [0..624].
    void get_state(MutArrayRef<u32> out_state, usize& out_index) const noexcept;

    /// Restore state; guards against the absorbing all-zero state.
    void set_state(ArrayRef<u32> in_state, usize in_index) noexcept;

private:
    void twist() noexcept;

    u32 mt_[kStateSize] = {};
    usize mti_ = kStateSize;
};

using DefaultRng = Xoshiro256PlusPlus;

// ============================================================================
// 3. Internal Generator Adapters & Shared Tables
// ============================================================================

namespace random_detail {

// 256-layer Marsaglia-Tsang Ziggurat tables for N(0, 1) (r = 3.6541528853610088).
// kZigguratX[0] = 0.0; kZigguratX[k+1] is the right endpoint of strip k (0..254),
// and kZigguratX[256] = v / f(r) is the virtual width of the base/tail strip.
extern const f64 kZigguratX[257];
extern const f64 kZigguratF[257];

// Portable 64x64 -> 128-bit unsigned multiplication (zero compiler extensions).
constexpr void mul_u64_hi_lo(u64 a, u64 b, u64& hi, u64& lo) noexcept {
    const u64 a_lo = a & 0xFFFFFFFFULL;
    const u64 a_hi = a >> 32;
    const u64 b_lo = b & 0xFFFFFFFFULL;
    const u64 b_hi = b >> 32;

    const u64 p0 = a_lo * b_lo;
    const u64 p1 = a_lo * b_hi;
    const u64 p2 = a_hi * b_lo;
    const u64 p3 = a_hi * b_hi;

    const u64 mid = (p0 >> 32) + (p1 & 0xFFFFFFFFULL) + (p2 & 0xFFFFFFFFULL);
    hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    lo = (mid << 32) | (p0 & 0xFFFFFFFFULL);
}

template <typename G>
[[nodiscard]] inline u64 draw_u64(G& rng) noexcept {
    if constexpr (requires { rng.next_u64(); }) {
        return as<u64>(rng.next_u64());
    } else if constexpr (requires { rng.next_u32(); }) {
        const u64 hi = as<u64>(rng.next_u32());
        const u64 lo = as<u64>(rng.next_u32());
        return (hi << 32) | lo;
    } else {
        using R = decltype(rng());
        if constexpr (sizeof(R) >= 8) {
            return as<u64>(rng());
        } else {
            const u64 hi = as<u64>(as<u32>(rng()));
            const u64 lo = as<u64>(as<u32>(rng()));
            return (hi << 32) | lo;
        }
    }
}

template <typename G>
[[nodiscard]] inline u32 draw_u32(G& rng) noexcept {
    if constexpr (requires { rng.next_u32(); }) {
        return as<u32>(rng.next_u32());
    } else if constexpr (requires { rng.next_u64(); }) {
        return as<u32>(rng.next_u64() >> 32);
    } else {
        using R = decltype(rng());
        if constexpr (sizeof(R) >= 8) {
            return as<u32>(as<u64>(rng()) >> 32);
        } else {
            return as<u32>(rng());
        }
    }
}

// Accurate ln(k!) for all k >= 0 (< 1 ULP).
[[nodiscard]] inline f64 log_factorial(u64 k) noexcept {
    static constexpr f64 kSmallLogFact[33] = {
        0.00000000000000000000e+00, // 0!
        0.00000000000000000000e+00, // 1!
        6.93147180559945309417e-01, // 2!
        1.79175946922805500081e+00, // 3!
        3.17805383034794561965e+00, // 4!
        4.78749174278204599425e+00, // 5!
        6.57925121201010099506e+00, // 6!
        8.52516136106541430017e+00, // 7!
        1.06046029027452502284e+01, // 8!
        1.28018274800814696112e+01, // 9!
        1.51044125730755152952e+01, // 10!
        1.75023078458738858393e+01, // 11!
        1.99872144956618861495e+01, // 12!
        2.25521638531234228856e+01, // 13!
        2.51912211827386815000e+01, // 14!
        2.78992713838408915661e+01, // 15!
        3.06718601060806728038e+01, // 16!
        3.35050734501368888840e+01, // 17!
        3.63954452080330535762e+01, // 18!
        3.93398841871994940362e+01, // 19!
        4.23356164607534850297e+01, // 20!
        4.53801388984769080262e+01, // 21!
        4.84711813518352238796e+01, // 22!
        5.16066755677643735704e+01, // 23!
        5.47847293981123191901e+01, // 24!
        5.80036052229805199393e+01, // 25!
        6.12617017610020019848e+01, // 26!
        6.45575386270063310590e+01, // 27!
        6.78897431371815349829e+01, // 28!
        7.12570389671680090101e+01, // 29!
        7.46582363488301643855e+01, // 30!
        7.80922235533153106335e+01, // 31!
        8.15579594561150371785e+01, // 32!
    };
    if (k <= 32ULL) {
        return kSmallLogFact[k];
    }
    const f64 x = as<f64>(k);
    const f64 inv = 1.0 / x;
    const f64 inv2 = inv * inv;
    constexpr f64 kHalfLogTau = 0.91893853320467274178032973640562; // 0.5 * ln(2*pi)
    const f64 corr = inv * ((1.0 / 12.0) - inv2 * ((1.0 / 360.0) - inv2 * ((1.0 / 1260.0) - inv2 * (1.0 / 1680.0))));
    return (x + 0.5) * keel::log(x) - x + kHalfLogTau + corr;
}

} // namespace random_detail

// ============================================================================
// 4. Uniform Distributions
// ============================================================================

/// Uniform double in [0, 1) with 53-bit precision.
template <typename G>
[[nodiscard]] inline f64 uniform_f64(G& rng) noexcept {
    if constexpr (requires { rng.next_f64(); }) {
        return rng.next_f64();
    } else {
        return as<f64>(random_detail::draw_u64(rng) >> 11) * (1.0 / 9007199254740992.0);
    }
}

/// Strictly positive uniform double in (0, 1) with 53-bit precision.
template <typename G>
[[nodiscard]] inline f64 uniform_f64_open(G& rng) noexcept {
    if constexpr (requires { rng.next_f64_open(); }) {
        return rng.next_f64_open();
    } else {
        for (;;) {
            const u64 bits = random_detail::draw_u64(rng) >> 11;
            if (bits != 0ULL) {
                return as<f64>(bits) * (1.0 / 9007199254740992.0);
            }
        }
    }
}

/// Uniform double in [a, b). Returns `a` if `!(a < b)`.
template <typename G>
[[nodiscard]] inline f64 uniform_f64(G& rng, f64 a, f64 b) noexcept {
    if (!(a < b)) return a;
    return a + (b - a) * uniform_f64(rng);
}

/// Uniform float in [0, 1) with 24-bit precision.
template <typename G>
[[nodiscard]] inline f32 uniform_f32(G& rng) noexcept {
    if constexpr (requires { rng.next_f32(); }) {
        return rng.next_f32();
    } else {
        return as<f32>(random_detail::draw_u32(rng) >> 8) * (1.0f / 16777216.0f);
    }
}

/// Uniform float in [a, b). Returns `a` if `!(a < b)`.
template <typename G>
[[nodiscard]] inline f32 uniform_f32(G& rng, f32 a, f32 b) noexcept {
    if (!(a < b)) return a;
    return a + (b - a) * uniform_f32(rng);
}

/// Unbiased uniform integer in [0, bound) via Lemire's nearly divisionless method.
/// Returns 0 if `bound <= 1`.
template <typename G>
[[nodiscard]] inline u64 uniform_u64_bound(G& rng, u64 bound) noexcept {
    if (bound <= 1ULL) return 0ULL;
    u64 hi = 0;
    u64 lo = 0;
    random_detail::mul_u64_hi_lo(random_detail::draw_u64(rng), bound, hi, lo);
    if (lo < bound) {
        const u64 threshold = (0ULL - bound) % bound;
        while (lo < threshold) {
            random_detail::mul_u64_hi_lo(random_detail::draw_u64(rng), bound, hi, lo);
        }
    }
    return hi;
}

/// Unbiased uniform u64 in inclusive range [lo, hi]. Returns `lo` if `lo >= hi`.
template <typename G>
[[nodiscard]] inline u64 uniform_u64(G& rng, u64 lo, u64 hi) noexcept {
    if (lo >= hi) return lo;
    const u64 span = hi - lo;
    if (span == Limits<u64>::kMax) {
        return random_detail::draw_u64(rng);
    }
    return lo + uniform_u64_bound(rng, span + 1ULL);
}

/// Unbiased uniform i64 in inclusive range [lo, hi]. Returns `lo` if `lo >= hi`.
template <typename G>
[[nodiscard]] inline i64 uniform_i64(G& rng, i64 lo, i64 hi) noexcept {
    if (lo >= hi) return lo;
    const u64 span = as<u64>(hi) - as<u64>(lo);
    if (span == Limits<u64>::kMax) {
        return as<i64>(random_detail::draw_u64(rng));
    }
    return as<i64>(as<u64>(lo) + uniform_u64_bound(rng, span + 1ULL));
}

/// Unbiased uniform usize in inclusive range [lo, hi]. Returns `lo` if `lo >= hi`.
template <typename G>
[[nodiscard]] inline usize uniform_usize(G& rng, usize lo, usize hi) noexcept {
    if (lo >= hi) return lo;
    return as<usize>(uniform_u64(rng, as<u64>(lo), as<u64>(hi)));
}

/// Bernoulli trial with success probability `p` in [0, 1].
template <typename G>
[[nodiscard]] inline bool bernoulli(G& rng, f64 p = 0.5) noexcept {
    if (!(p > 0.0)) return false;
    if (p >= 1.0) return true;
    return uniform_f64(rng) < p;
}

// ============================================================================
// 5. Continuous Distributions
// ============================================================================

/// Standard normal N(0, 1) via 256-layer Marsaglia-Tsang Ziggurat.
template <typename G>
[[nodiscard]] inline f64 normal_f64(G& rng) noexcept {
    for (;;) {
        const u64 bits = random_detail::draw_u64(rng);
        const usize k = as<usize>(bits >> 56);
        const i64 u53 = as<i64>(bits & 0x001FFFFFFFFFFFFFULL) - (i64{1} << 52);
        const f64 u = as<f64>(u53) * (1.0 / 4503599627370496.0);
        const f64 z = u * random_detail::kZigguratX[k + 1];
        if (keel::abs(z) < random_detail::kZigguratX[k]) {
            return z;
        }
        if (k == 255u) {
            constexpr f64 kR = 0x1.d3bb48209ad36p+1; // kZigguratX[255]
            constexpr f64 kInvR = 1.0 / kR;
            for (;;) {
                const f64 tx = -keel::log(uniform_f64_open(rng)) * kInvR;
                const f64 ty = -keel::log(uniform_f64_open(rng));
                if (ty + ty >= tx * tx) {
                    return (u53 >= 0) ? (kR + tx) : -(kR + tx);
                }
            }
        } else {
            const f64 y = (random_detail::kZigguratF[k] - random_detail::kZigguratF[k + 1]) * uniform_f64(rng);
            if (y < keel::exp(-0.5 * z * z) - random_detail::kZigguratF[k + 1]) {
                return z;
            }
        }
    }
}

/// Normal N(mean, stddev^2).
template <typename G>
[[nodiscard]] inline f64 normal_f64(G& rng, f64 mean, f64 stddev) noexcept {
    return mean + stddev * normal_f64(rng);
}

/// Standard normal float N(0, 1).
template <typename G>
[[nodiscard]] inline f32 normal_f32(G& rng) noexcept {
    return as<f32>(normal_f64(rng));
}

/// Normal float N(mean, stddev^2).
template <typename G>
[[nodiscard]] inline f32 normal_f32(G& rng, f32 mean, f32 stddev) noexcept {
    return mean + stddev * as<f32>(normal_f64(rng));
}

/// Log-normal distribution: exp(mu + sigma * N(0, 1)).
template <typename G>
[[nodiscard]] inline f64 lognormal_f64(G& rng, f64 mu = 0.0, f64 sigma = 1.0) noexcept {
    return keel::exp(mu + sigma * normal_f64(rng));
}

/// Exponential distribution with rate parameter `rate > 0` (mean = 1 / rate).
template <typename G>
[[nodiscard]] inline f64 exponential_f64(G& rng, f64 rate = 1.0) noexcept {
    if (!(rate > 0.0) || !keel::is_finite(rate)) return 0.0;
    return -keel::log(uniform_f64_open(rng)) / rate;
}

/// Gamma(shape, scale) via Marsaglia-Tsang (shape >= 1) and Ahrens-Dieter boost
/// (0 < shape < 1). Mean = shape * scale.
template <typename G>
[[nodiscard]] inline f64 gamma_f64(G& rng, f64 shape, f64 scale = 1.0) noexcept {
    if (!(shape > 0.0) || !keel::is_finite(shape) || !(scale > 0.0) || !keel::is_finite(scale)) return 0.0;
    if (shape < 1.0) {
        const f64 g = gamma_f64(rng, shape + 1.0, scale);
        const f64 u = uniform_f64_open(rng);
        return g * keel::pow(u, 1.0 / shape);
    }
    const f64 d = shape - (1.0 / 3.0);
    const f64 c = 1.0 / keel::sqrt(9.0 * d);
    for (;;) {
        const f64 x = normal_f64(rng);
        f64 v = 1.0 + c * x;
        if (v <= 0.0) continue;
        v = v * v * v;
        const f64 u = uniform_f64_open(rng);
        const f64 x2 = x * x;
        if (u < 1.0 - 0.0331 * x2 * x2) {
            return d * v * scale;
        }
        if (keel::log(u) < 0.5 * x2 + d * (1.0 - v + keel::log(v))) {
            return d * v * scale;
        }
    }
}

/// Beta(a, b) on [0, 1] for a > 0, b > 0.
template <typename G>
[[nodiscard]] inline f64 beta_f64(G& rng, f64 a, f64 b) noexcept {
    if (!(a > 0.0) || !keel::is_finite(a) || !(b > 0.0) || !keel::is_finite(b)) return 0.0;
    const f64 x = gamma_f64(rng, a, 1.0);
    const f64 y = gamma_f64(rng, b, 1.0);
    const f64 sum = x + y;
    if (sum > 0.0) {
        return x / sum;
    }
    // Underflow fallback for extremely small a, b via log-space Johnk method.
    for (;;) {
        const f64 log_u = keel::log(uniform_f64_open(rng)) / a;
        const f64 log_v = keel::log(uniform_f64_open(rng)) / b;
        const f64 mx = (log_u > log_v) ? log_u : log_v;
        const f64 log_sum = mx + keel::log(keel::exp(log_u - mx) + keel::exp(log_v - mx));
        if (log_sum <= 0.0) {
            return keel::exp(log_u - log_sum);
        }
    }
}

/// Chi-squared distribution with `df > 0` degrees of freedom.
template <typename G>
[[nodiscard]] inline f64 chi_squared_f64(G& rng, f64 df) noexcept {
    if (!(df > 0.0) || !keel::is_finite(df)) return 0.0;
    return gamma_f64(rng, 0.5 * df, 2.0);
}

/// Student's t distribution with `df > 0` degrees of freedom.
template <typename G>
[[nodiscard]] inline f64 student_t_f64(G& rng, f64 df) noexcept {
    if (!(df > 0.0) || !keel::is_finite(df)) return 0.0;
    const f64 z = normal_f64(rng);
    f64 v = chi_squared_f64(rng, df);
    if (v <= 0.0) {
        v = Limits<f64>::kMinPositive;
    }
    return z / keel::sqrt(v / df);
}

/// Weibull distribution with `shape > 0` (k) and `scale > 0` (lambda).
/// CDF: F(x) = 1 - exp(-(x / scale)^shape).
template <typename G>
[[nodiscard]] inline f64 weibull_f64(G& rng, f64 shape, f64 scale = 1.0) noexcept {
    if (!(shape > 0.0) || !keel::is_finite(shape) || !(scale > 0.0) || !keel::is_finite(scale)) return 0.0;
    return scale * keel::pow(-keel::log(uniform_f64_open(rng)), 1.0 / shape);
}

// ============================================================================
// 6. Discrete & Combinatorial Distributions
// ============================================================================

/// Poisson distribution with mean `mean >= 0`.
/// Uses Knuth's method for mean < 30 and Hormann's PTRS for mean >= 30.
template <typename G>
[[nodiscard]] inline u64 poisson_u64(G& rng, f64 mean) noexcept {
    if (!(mean > 0.0) || !keel::is_finite(mean)) return 0ULL;
    if (mean >= 18446744073709551615.0) return Limits<u64>::kMax;

    if (mean < 30.0) {
        const f64 limit = keel::exp(-mean);
        f64 prod = 1.0;
        u64 k = 0;
        do {
            ++k;
            prod *= uniform_f64_open(rng);
        } while (prod > limit);
        return k - 1ULL;
    }

    // Hormann (1993) PTRS: Transformed Rejection with Squeeze.
    const f64 smu = keel::sqrt(mean);
    const f64 b = 0.931 + 2.53 * smu;
    const f64 a = -0.059 + 0.02483 * b;
    const f64 inv_alpha = 1.1239 + 1.1328 / (b - 3.4);
    const f64 v_r = 0.9277 - 3.6224 / (b - 2.0);
    const f64 log_mean = keel::log(mean);

    for (;;) {
        const f64 u = uniform_f64(rng) - 0.5;
        const f64 v = uniform_f64_open(rng);
        const f64 us = 0.5 - keel::abs(u);
        const f64 kf = keel::floor((2.0 * a / us + b) * u + mean + 0.43);
        if (kf < 0.0 || kf >= 18446744073709551615.0) continue;
        const u64 k = as<u64>(kf);
        if (us >= 0.07 && v <= v_r) return k;
        if (us < 0.013 && v > us) continue;
        if (keel::log(v * inv_alpha / (a / (us * us) + b)) <=
            -mean + as<f64>(k) * log_mean - random_detail::log_factorial(k)) {
            return k;
        }
    }
}

/// Binomial(n, p) count of successes in `n` trials with probability `p`.
/// Uses inverse CDF (BINV) for n*min(p, 1-p) < 10 and BTPE (Kachitvichyanukul
/// & Schmeiser 1988) for larger means.
template <typename G>
[[nodiscard]] inline u64 binomial_u64(G& rng, u64 n, f64 p) noexcept {
    if (n == 0ULL || !(p > 0.0)) return 0ULL;
    if (p >= 1.0) return n;

    const bool flipped = (p > 0.5);
    const f64 pp = flipped ? (1.0 - p) : p;
    const f64 q = 1.0 - pp;
    const f64 nf = as<f64>(n);
    const f64 np = nf * pp;

    u64 result = 0;
    if (np < 10.0) {
        // BINV: inverse CDF search.
        const f64 s = pp / q;
        const f64 a = (nf + 1.0) * s;
        f64 r = keel::pow(q, nf);
        f64 u = uniform_f64(rng);
        u64 x = 0;
        while (u > r && x < n) {
            u -= r;
            ++x;
            r *= (a / as<f64>(x) - s);
            if (r <= 0.0) break;
        }
        result = x;
    } else if (n > (u64{1} << 52)) {
        // Normal approximation for astronomically large n where f64 loses integer granularity.
        const f64 stddev = keel::sqrt(np * q);
        const f64 sample = keel::round(np + stddev * normal_f64(rng));
        if (sample <= 0.0) {
            result = 0ULL;
        } else if (sample >= nf) {
            result = n;
        } else {
            result = as<u64>(sample);
        }
    } else {
        // BTPE: Binomial Triangle-Parallelogram-Exponential rejection.
        const f64 fm = np + pp;
        const i64 m = as<i64>(fm);
        const f64 npq = np * q;
        const f64 p1 = keel::floor(2.195 * keel::sqrt(npq) - 4.6 * q) + 0.5;
        const f64 xm = as<f64>(m) + 0.5;
        const f64 xl = xm - p1;
        const f64 xr = xm + p1;
        const f64 c = 0.134 + 20.5 / (15.3 + as<f64>(m));
        const f64 al = (fm - xl) / (fm - xl * pp);
        const f64 laml = al * (1.0 + 0.5 * al);
        const f64 ar = (xr - fm) / (xr * q);
        const f64 lamr = ar * (1.0 + 0.5 * ar);
        const f64 p2 = p1 * (1.0 + c + c);
        const f64 p3 = p2 + c / laml;
        const f64 p4 = p3 + c / lamr;
        const f64 r_ratio = pp / q;
        const f64 log_pq = keel::log(r_ratio);
        const f64 g_val = (nf + 1.0) * r_ratio;

        i64 y = 0;
        for (;;) {
            const f64 u = uniform_f64(rng) * p4;
            f64 v = uniform_f64_open(rng);
            if (u <= p1) {
                y = as<i64>(keel::floor(xm - p1 * v + u));
                break;
            }
            if (u <= p2) {
                const f64 x = xl + (u - p1) / c;
                v = v * c + 1.0 - keel::abs(xm - x) / p1;
                if (v > 1.0 || v <= 0.0) continue;
                y = as<i64>(keel::floor(x));
            } else if (u <= p3) {
                const f64 yf = keel::floor(xl + keel::log(v) / laml);
                if (yf < 0.0) continue;
                y = as<i64>(yf);
                v = v * (u - p2) * laml;
            } else {
                const f64 yf = keel::floor(xr - keel::log(v) / lamr);
                if (yf > nf) continue;
                y = as<i64>(yf);
                v = v * (u - p3) * lamr;
            }

            const i64 k = (y >= m) ? (y - m) : (m - y);
            if (k <= 20 || as<f64>(k) >= 0.5 * npq - 1.0) {
                f64 f = 1.0;
                if (m < y) {
                    for (i64 i = m + 1; i <= y; ++i) {
                        f *= (g_val / as<f64>(i) - r_ratio);
                    }
                } else if (m > y) {
                    for (i64 i = y + 1; i <= m; ++i) {
                        f /= (g_val / as<f64>(i) - r_ratio);
                    }
                }
                if (v <= f) break;
            } else {
                const f64 kf = as<f64>(k);
                const f64 rho = (kf / npq) * ((kf * (kf / 3.0 + 0.625) + (1.0 / 6.0)) / npq + 0.5);
                const f64 t = -(kf * kf) / (2.0 * npq);
                const f64 log_v = keel::log(v);
                if (log_v < t - rho) break;
                if (log_v > t + rho) continue;
                const f64 log_f = (random_detail::log_factorial(as<u64>(m)) +
                                   random_detail::log_factorial(n - as<u64>(m)) -
                                   random_detail::log_factorial(as<u64>(y)) -
                                   random_detail::log_factorial(n - as<u64>(y))) +
                                  as<f64>(y - m) * log_pq;
                if (log_v <= log_f) break;
            }
        }
        result = as<u64>(y);
    }

    return flipped ? (n - result) : result;
}

/// Geometric distribution: number of failures before the first success (0-based),
/// P(X = k) = (1 - p)^k * p.
template <typename G>
[[nodiscard]] inline u64 geometric_u64(G& rng, f64 p) noexcept {
    if (!(p > 0.0)) return Limits<u64>::kMax;
    if (p >= 1.0) return 0ULL;
    const f64 val = keel::floor(keel::log(uniform_f64_open(rng)) / keel::log1p(-p));
    if (val <= 0.0) return 0ULL;
    if (val >= 18446744073709551615.0) return Limits<u64>::kMax;
    return as<u64>(val);
}

/// Discrete categorical draw from non-negative `weights`.
/// Returns an index in [0, weights.size()), or 0 if empty or all weights <= 0.
template <typename G>
[[nodiscard]] inline usize discrete_index(G& rng, ArrayRef<f64> weights) noexcept {
    if (weights.empty()) return 0;
    f64 max_w = 0.0;
    usize last_positive = 0;
    for (usize i = 0; i < weights.size(); ++i) {
        const f64 w = weights[i];
        if (w > 0.0 && keel::is_finite(w)) {
            if (w > max_w) max_w = w;
            last_positive = i;
        }
    }
    if (!(max_w > 0.0)) return 0;
    const f64 inv_max = 1.0 / max_w;
    f64 total = 0.0;
    for (usize i = 0; i < weights.size(); ++i) {
        const f64 w = weights[i];
        if (w > 0.0 && keel::is_finite(w)) {
            total += w * inv_max;
        }
    }
    const f64 target = uniform_f64(rng) * total;
    f64 accum = 0.0;
    for (usize i = 0; i < weights.size(); ++i) {
        const f64 w = weights[i];
        if (w > 0.0 && keel::is_finite(w)) {
            accum += w * inv_max;
            if (target < accum) return i;
        }
    }
    return last_positive;
}

/// In-place Fisher-Yates shuffle.
template <typename G, typename T>
inline void shuffle(G& rng, MutArrayRef<T> data) noexcept {
    for (usize i = data.size(); i > 1; --i) {
        const usize j = as<usize>(uniform_u64_bound(rng, as<u64>(i)));
        if (j != i - 1) {
            T tmp = static_cast<T&&>(data[i - 1]);
            data[i - 1] = static_cast<T&&>(data[j]);
            data[j] = static_cast<T&&>(tmp);
        }
    }
}

/// Uniformly sample `k = min(n, out.size())` distinct indices from [0, n)
/// without replacement in random order (zero heap allocations).
/// Returns the number of indices written into `out`.
template <typename G>
inline usize sample_indices(G& rng, usize n, MutArrayRef<usize> out) noexcept {
    const usize k = (n < out.size()) ? n : out.size();
    if (k == 0) return 0;
    for (usize i = 0; i < k; ++i) {
        out[i] = i;
    }
    for (usize i = k; i < n; ++i) {
        const usize j = as<usize>(uniform_u64_bound(rng, as<u64>(i + 1)));
        if (j < k) {
            out[j] = i;
        }
    }
    shuffle(rng, MutArrayRef<usize>(out.data(), k));
    return k;
}

} // namespace keel::random
