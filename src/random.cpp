#include "keel/random.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <stdlib.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__) || defined(__ANDROID__) || defined(__EMSCRIPTEN__)
#include <sys/random.h>
#endif
#endif

namespace keel {

// ============================================================================
// 1. OS Cryptographic Entropy
// ============================================================================

Error os_random_bytes(MutArrayRef<u8> out) noexcept {
    if (out.empty()) {
        return Error::ok();
    }

#if defined(_WIN32)
    u8* ptr = out.data();
    usize remaining = out.size();
    while (remaining > 0) {
        const ULONG chunk = (remaining > 0x7FFFFFFFu) ? 0x7FFFFFFFu : static_cast<ULONG>(remaining);
        const NTSTATUS status = BCryptGenRandom(nullptr, ptr, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            return Error{ErrorCode::IoError, static_cast<i32>(status)};
        }
        ptr += chunk;
        remaining -= chunk;
    }
    return Error::ok();

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    arc4random_buf(out.data(), out.size());
    return Error::ok();

#else
    u8* ptr = out.data();
    usize remaining = out.size();

#if defined(__linux__) || defined(__ANDROID__) || defined(__EMSCRIPTEN__)
    bool use_urandom = false;
    while (remaining > 0) {
        const ssize_t n = ::getrandom(ptr, remaining, 0);
        if (n > 0) {
            ptr += static_cast<usize>(n);
            remaining -= static_cast<usize>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && errno == ENOSYS) {
            use_urandom = true;
            break;
        }
        return Error{ErrorCode::IoError, static_cast<i32>(errno)};
    }
    if (!use_urandom) {
        return Error::ok();
    }
#endif

    int fd = -1;
    do {
        fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        return Error{ErrorCode::IoError, static_cast<i32>(errno)};
    }

    while (remaining > 0) {
        const ssize_t n = ::read(fd, ptr, remaining);
        if (n > 0) {
            ptr += static_cast<usize>(n);
            remaining -= static_cast<usize>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        const i32 err = (n < 0) ? static_cast<i32>(errno) : 0;
        ::close(fd);
        return Error{ErrorCode::IoError, err};
    }

    ::close(fd);
    return Error::ok();
#endif
}

Result<u64, Error> os_random_u64() noexcept {
    u8 buf[8] = {};
    const Error err = os_random_bytes(MutArrayRef<u8>(buf, 8));
    if (err.is_err()) {
        return err;
    }
    const u64 val = static_cast<u64>(buf[0]) | (static_cast<u64>(buf[1]) << 8) | (static_cast<u64>(buf[2]) << 16) |
                    (static_cast<u64>(buf[3]) << 24) | (static_cast<u64>(buf[4]) << 32) |
                    (static_cast<u64>(buf[5]) << 40) | (static_cast<u64>(buf[6]) << 48) |
                    (static_cast<u64>(buf[7]) << 56);
    return val;
}

Result<u32, Error> os_random_u32() noexcept {
    u8 buf[4] = {};
    const Error err = os_random_bytes(MutArrayRef<u8>(buf, 4));
    if (err.is_err()) {
        return err;
    }
    const u32 val = static_cast<u32>(buf[0]) | (static_cast<u32>(buf[1]) << 8) | (static_cast<u32>(buf[2]) << 16) |
                    (static_cast<u32>(buf[3]) << 24);
    return val;
}

// ============================================================================
// 2. Mt19937 (Matsumoto-Nishimura 1998)
// ============================================================================

namespace {
constexpr usize kMtN = Mt19937::kStateSize;
constexpr usize kMtM = 397;
constexpr u32 kMtMatrixA = 0x9908b0dfu;
constexpr u32 kMtUpperMask = 0x80000000u;
constexpr u32 kMtLowerMask = 0x7fffffffu;
} // namespace

Mt19937::Mt19937(u32 s) noexcept {
    seed(s);
}

void Mt19937::seed(u32 s) noexcept {
    mt_[0] = s;
    for (usize i = 1; i < kMtN; ++i) {
        mt_[i] = 1812433253u * (mt_[i - 1] ^ (mt_[i - 1] >> 30)) + static_cast<u32>(i);
    }
    mti_ = kMtN;
}

void Mt19937::seed_array(ArrayRef<u32> key) noexcept {
    if (key.empty()) {
        seed(5489u);
        return;
    }
    seed(19650218u);
    usize i = 1;
    usize j = 0;
    usize k = (kMtN > key.size()) ? kMtN : key.size();
    for (; k > 0; --k) {
        mt_[i] = (mt_[i] ^ ((mt_[i - 1] ^ (mt_[i - 1] >> 30)) * 1664525u)) + key[j] + static_cast<u32>(j);
        ++i;
        ++j;
        if (i >= kMtN) {
            mt_[0] = mt_[kMtN - 1];
            i = 1;
        }
        if (j >= key.size()) {
            j = 0;
        }
    }
    for (k = kMtN - 1; k > 0; --k) {
        mt_[i] = (mt_[i] ^ ((mt_[i - 1] ^ (mt_[i - 1] >> 30)) * 1566083941u)) - static_cast<u32>(i);
        ++i;
        if (i >= kMtN) {
            mt_[0] = mt_[kMtN - 1];
            i = 1;
        }
    }
    mt_[0] = kMtUpperMask; // Assures non-zero initial array.
    mti_ = kMtN;
}

void Mt19937::twist() noexcept {
    static constexpr u32 kMag01[2] = {0u, kMtMatrixA};
    usize kk = 0;
    for (; kk < kMtN - kMtM; ++kk) {
        const u32 y = (mt_[kk] & kMtUpperMask) | (mt_[kk + 1] & kMtLowerMask);
        mt_[kk] = mt_[kk + kMtM] ^ (y >> 1) ^ kMag01[y & 1u];
    }
    for (; kk < kMtN - 1; ++kk) {
        const u32 y = (mt_[kk] & kMtUpperMask) | (mt_[kk + 1] & kMtLowerMask);
        mt_[kk] = mt_[kk + (kMtM - kMtN)] ^ (y >> 1) ^ kMag01[y & 1u];
    }
    const u32 y = (mt_[kMtN - 1] & kMtUpperMask) | (mt_[0] & kMtLowerMask);
    mt_[kMtN - 1] = mt_[kMtM - 1] ^ (y >> 1) ^ kMag01[y & 1u];
    mti_ = 0;
}

u32 Mt19937::next_u32() noexcept {
    if (mti_ >= kMtN) {
        twist();
    }
    u32 y = mt_[mti_++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680u;
    y ^= (y << 15) & 0xefc60000u;
    y ^= (y >> 18);
    return y;
}

u64 Mt19937::next_u64() noexcept {
    const u64 hi = static_cast<u64>(next_u32());
    const u64 lo = static_cast<u64>(next_u32());
    return (hi << 32) | lo;
}

f64 Mt19937::next_f64() noexcept {
    const u32 a = next_u32() >> 5;
    const u32 b = next_u32() >> 6;
    return (static_cast<f64>(a) * 67108864.0 + static_cast<f64>(b)) * (1.0 / 9007199254740992.0);
}

f64 Mt19937::next_f64_open() noexcept {
    for (u32 tries = 0; tries < 1024u; ++tries) {
        const u32 a = next_u32() >> 5;
        const u32 b = next_u32() >> 6;
        if ((a | b) != 0u) {
            return (static_cast<f64>(a) * 67108864.0 + static_cast<f64>(b)) * (1.0 / 9007199254740992.0);
        }
    }
    seed(5489u);
    const u32 a = next_u32() >> 5;
    const u32 b = next_u32() >> 6;
    return (static_cast<f64>(a) * 67108864.0 + static_cast<f64>(b)) * (1.0 / 9007199254740992.0);
}

f32 Mt19937::next_f32() noexcept {
    return static_cast<f32>(next_u32() >> 8) * (1.0f / 16777216.0f);
}

void Mt19937::get_state(MutArrayRef<u32> out_state, usize& out_index) const noexcept {
    const usize count = (out_state.size() < kMtN) ? out_state.size() : kMtN;
    for (usize i = 0; i < count; ++i) {
        out_state[i] = mt_[i];
    }
    out_index = mti_;
}

void Mt19937::set_state(ArrayRef<u32> in_state, usize in_index) noexcept {
    if (in_state.size() < kMtN) {
        seed(5489u);
        return;
    }
    bool any_non_zero = ((in_state[0] & kMtUpperMask) != 0u);
    for (usize i = 0; i < kMtN; ++i) {
        mt_[i] = in_state[i];
        if (i > 0 && in_state[i] != 0u) {
            any_non_zero = true;
        }
    }
    if (!any_non_zero) {
        mt_[0] = kMtUpperMask; // Prevent absorbing all-zero MT19937 state.
    }
    mti_ = (in_index > kMtN) ? kMtN : in_index;
}

// ============================================================================
// 3. 256-Layer Marsaglia-Tsang Ziggurat Tables for N(0, 1)
// ============================================================================

namespace random_detail {

const f64 kZigguratX[257] = {
    0x0.0p+0, 0x1.b8d0be3fdf611p-3, 0x1.250af3c2c5b75p-2, 0x1.57cb938443b37p-2,
    0x1.801fce82fa6ecp-2, 0x1.a230c2e4cd0a4p-2, 0x1.c004d2f3861e9p-2, 0x1.dac2f5a747259p-2,
    0x1.f32482d4cd5bep-2, 0x1.04d32278ebba4p-1, 0x1.0f5053b025d3fp-1, 0x1.192a697413673p-1,
    0x1.227a28f7a1aeap-1, 0x1.2b52e3863d879p-1, 0x1.33c3fc05791ebp-1, 0x1.3bd9ec1a2b127p-1,
    0x1.439ef8dff9b50p-1, 0x1.4b1bb363dfea6p-1, 0x1.52575621ad373p-1, 0x1.59580a707ce95p-1,
    0x1.60231cfd97eecp-1, 0x1.66bd261a37c3ap-1, 0x1.6d2a29200056ep-1, 0x1.736dad346f8a8p-1,
    0x1.798ad10b32a78p-1, 0x1.7f845ad46f546p-1, 0x1.855cc53430a73p-1, 0x1.8b1649e7b769ep-1,
    0x1.90b2ea94ecf94p-1, 0x1.96347822c1eeep-1, 0x1.9b9c98e38c542p-1, 0x1.a0eccdca4a72fp-1,
    0x1.a62676d77cd55p-1, 0x1.ab4ad6e10162cp-1, 0x1.b05b16d136c99p-1, 0x1.b558487427a28p-1,
    0x1.ba4368e529f38p-1, 0x1.bf1d62abf8232p-1, 0x1.c3e70f9594ef3p-1, 0x1.c8a13a5323b61p-1,
    0x1.cd4c9fe722688p-1, 0x1.d1e9f0e80b747p-1, 0x1.d679d29e41f0ep-1, 0x1.dafce0023b8bep-1,
    0x1.df73aa9f17655p-1, 0x1.e3debb5d2edfep-1, 0x1.e83e9337a6f04p-1, 0x1.ec93abdf982cdp-1,
    0x1.f0de784f06226p-1, 0x1.f51f654d8f686p-1, 0x1.f956d9e87d7aep-1, 0x1.fd8537dfa2ea8p-1,
    0x1.00d56e04234e1p+0, 0x1.02e40f5398fb0p+0, 0x1.04eea9e16a5ecp+0, 0x1.06f565b729ffap+0,
    0x1.08f869071f40bp+0, 0x1.0af7d84bc611bp+0, 0x1.0cf3d664bcc83p+0, 0x1.0eec84b160858p+0,
    0x1.10e20329515e6p+0, 0x1.12d4707310fd2p+0, 0x1.14c3e9f8e9132p+0, 0x1.16b08bfc42021p+0,
    0x1.189a71a78da30p+0, 0x1.1a81b51ee6d8cp+0, 0x1.1c666f8f82ab5p+0, 0x1.1e48b93e0d41ap+0,
    0x1.2028a9940a093p+0, 0x1.2206572c4c6dbp+0, 0x1.23e1d7de9c31cp+0, 0x1.25bb40ca96c02p+0,
    0x1.2792a661dd38cp+0, 0x1.29681c719d716p+0, 0x1.2b3bb62b82ecdp+0, 0x1.2d0d862e1b84cp+0,
    0x1.2edd9e8cba99fp+0, 0x1.30ac10d6e48d1p+0, 0x1.3278ee1f4b92cp+0, 0x1.3444470265e9dp+0,
    0x1.360e2baca52dbp+0, 0x1.37d6abe055865p+0, 0x1.399dd6fb2b263p+0, 0x1.3b63bbfb83d17p+0,
    0x1.3d28698561defp+0, 0x1.3eebede725a92p+0, 0x1.40ae571e09e82p+0, 0x1.426fb2da6744cp+0,
    0x1.44300e83c30a8p+0, 0x1.45ef773cac76fp+0, 0x1.47adf9e66c341p+0, 0x1.496ba32488f20p+0,
    0x1.4b287f6024168p+0, 0x1.4ce49acb311e9p+0, 0x1.4ea001638a601p+0, 0x1.505abef5e5561p+0,
    0x1.5214df20a8b6dp+0, 0x1.53ce6d56a6663p+0, 0x1.558774e1bb2c9p+0, 0x1.574000e555f67p+0,
    0x1.58f81c60e8522p+0, 0x1.5aafd23241b44p+0, 0x1.5c672d17d7331p+0, 0x1.5e1e37b2f8ce6p+0,
    0x1.5fd4fc89f5e4ap+0, 0x1.618b860a31fd9p+0, 0x1.6341de8a2b0b5p+0, 0x1.64f8104b72608p+0,
    0x1.66ae257c9966fp+0, 0x1.6864283b1313ep+0, 0x1.6a1a22950b2aep+0, 0x1.6bd01e8b343c2p+0,
    0x1.6d8626128d366p+0, 0x1.6f3c43161f84cp+0, 0x1.70f27f78b68dap+0, 0x1.72a8e516914d9p+0,
    0x1.745f7dc70eedcp+0, 0x1.7616535e57334p+0, 0x1.77cd6faeff44cp+0, 0x1.7984dc8babda8p+0,
    0x1.7b3ca3c8b1416p+0, 0x1.7cf4cf3db2307p+0, 0x1.7ead68c73ded7p+0, 0x1.80667a486ea0ep+0,
    0x1.82200dac88670p+0, 0x1.83da2ce899f01p+0, 0x1.8594e1fd1f5c7p+0, 0x1.875036f7a7ebcp+0,
    0x1.890c35f47f71cp+0, 0x1.8ac8e9205c03cp+0, 0x1.8c865aba10c8ep+0, 0x1.8e44951446a38p+0,
    0x1.9003a2973b57bp+0, 0x1.91c38dc288338p+0, 0x1.9384612ef0b0ep+0, 0x1.954627903a28fp+0,
    0x1.9708ebb70d5ecp+0, 0x1.98ccb892e2a3bp+0, 0x1.9a919933f99acp+0, 0x1.9c5798cd5d92dp+0,
    0x1.9e1ec2b6f73fbp+0, 0x1.9fe7226fad238p+0, 0x1.a1b0c39f93686p+0, 0x1.a37bb21a2c869p+0,
    0x1.a547f9e0bbb80p+0, 0x1.a715a724aa9b9p+0, 0x1.a8e4c64a03134p+0, 0x1.aab563e9ff0f1p+0,
    0x1.ac878cd5af5b9p+0, 0x1.ae5b4e18bb326p+0, 0x1.b030b4fc3a103p+0, 0x1.b207cf09a9855p+0,
    0x1.b3e0aa0e00bf3p+0, 0x1.b5bb541ce3cfcp+0, 0x1.b797db93f891ap+0, 0x1.b9764f1e5f726p+0,
    0x1.bb56bdb852560p+0, 0x1.bd3936b2ec09bp+0, 0x1.bf1dc9b81ae78p+0, 0x1.c10486cec1699p+0,
    0x1.c2ed7e5f07a2cp+0, 0x1.c4d8c136e0d23p+0, 0x1.c6c6608ec86f8p+0, 0x1.c8b66e0eba610p+0,
    0x1.caa8fbd36a2a0p+0, 0x1.cc9e1c73bd68fp+0, 0x1.ce95e3068e033p+0, 0x1.d0906328b8f62p+0,
    0x1.d28db1037ef06p+0, 0x1.d48de1533c655p+0, 0x1.d691096e7f132p+0, 0x1.d8973f4d7fb8cp+0,
    0x1.daa0999206e66p+0, 0x1.dcad2f8fc48f9p+0, 0x1.debd195522e43p+0, 0x1.e0d06fb49d22cp+0,
    0x1.e2e74c4ea46e6p+0, 0x1.e501c99c1d171p+0, 0x1.e72002f97fe26p+0, 0x1.e94214b2abefap+0,
    0x1.eb681c0f76f10p+0, 0x1.ed9237610a720p+0, 0x1.efc086101ec94p+0, 0x1.f1f328ac25328p+0,
    0x1.f42a40fb74d7cp+0, 0x1.f665f20c9015ap+0, 0x1.f8a6604899785p+0, 0x1.faebb187122cep+0,
    0x1.fd360d22fe78ep+0, 0x1.ff859c118f60dp+0, 0x1.00ed447d3a078p+1, 0x1.021a8028fc93ep+1,
    0x1.034a983a902a2p+1, 0x1.047da4e3ef5cap+1, 0x1.05b3bf6adb37bp+1, 0x1.06ed023a72664p+1,
    0x1.082988f632e13p+1, 0x1.0969708e8a24ep+1, 0x1.0aacd7571c0bbp+1, 0x1.0bf3dd1eed445p+1,
    0x1.0d3ea34aa3d38p+1, 0x1.0e8d4cf11658dp+1, 0x1.0fdffefa69fb0p+1, 0x1.1136e0420704ap+1,
    0x1.129219bbb5d39p+1, 0x1.13f1d69c40975p+1, 0x1.1556448602e40p+1, 0x1.16bf93b9deeeep+1,
    0x1.182df74d21260p+1, 0x1.19a1a564eebb5p+1, 0x1.1b1ad777f2f8dp+1, 0x1.1c99ca971a694p+1,
    0x1.1e1ebfbe4ae37p+1, 0x1.1fa9fc2e2d903p+1, 0x1.213bc9d04cc87p+1, 0x1.22d477a6fd3ebp+1,
    0x1.24745a4ac9c20p+1, 0x1.261bcc77658d8p+1, 0x1.27cb2faa8592ap+1, 0x1.2982ecd770e72p+1,
    0x1.2b437532a0a56p+1, 0x1.2d0d43196db8dp+1, 0x1.2ee0db1a978f3p+1, 0x1.30becd256aee1p+1,
    0x1.32a7b5e68a4a9p+1, 0x1.349c405ae12a4p+1, 0x1.369d27a33a848p+1, 0x1.38ab392564101p+1,
    0x1.3ac7570ae88efp+1, 0x1.3cf27b317049fp+1, 0x1.3f2dbaa60f47cp+1, 0x1.417a49cb9e5d1p+1,
    0x1.43d9815545e8bp+1, 0x1.464ce44a73a0fp+1, 0x1.48d62759c43b4p+1, 0x1.4b7739d6b5a30p+1,
    0x1.4e3250dcd88fbp+1, 0x1.5109f53e9ac3cp+1, 0x1.54011523a7e3cp+1, 0x1.571b1a94ae410p+1,
    0x1.5a5c08b718dd4p+1, 0x1.5dc8a243ad0fbp+1, 0x1.61669cf861e54p+1, 0x1.653ce7b006af0p+1,
    0x1.69540be9fe5bbp+1, 0x1.6db6b8d09e227p+1, 0x1.72728f05f7a2ep+1, 0x1.7799556090677p+1,
    0x1.7d42df4d6ce84p+1, 0x1.839030529f22bp+1, 0x1.8ab0fbfaa7c0cp+1, 0x1.92ee0946f4494p+1,
    0x1.9cbee014057a7p+1, 0x1.a8fdc78947763p+1, 0x1.b981f3878fdadp+1, 0x1.d3bb48209ad36p+1,
    0x1.f493b7815d98bp+1,
};

const f64 kZigguratF[257] = {
    0x1.0000000000000p+0, 0x1.f446ac979f090p-1, 0x1.eb7545b6ca91ep-1, 0x1.e3f11e027f07ep-1,
    0x1.dd36fa704de9bp-1, 0x1.d70920657bcf6p-1, 0x1.d144978a119dfp-1, 0x1.cbd33a8a72df1p-1,
    0x1.c6a5ecea97880p-1, 0x1.c1b1cd9eebaeep-1, 0x1.bceeb4ee1dc84p-1, 0x1.b85653a8ff554p-1,
    0x1.b3e3a8234dd15p-1, 0x1.af92a3f6ce8a5p-1, 0x1.ab5fef17a2509p-1, 0x1.a748bd550c9e5p-1,
    0x1.a34aafdf5af11p-1, 0x1.9f63bee651fd9p-1, 0x1.9b9228d240681p-1, 0x1.97d4657617ac2p-1,
    0x1.94291c21b7a46p-1, 0x1.908f1bd317151p-1, 0x1.8d0554fe60aa9p-1, 0x1.898ad48badf01p-1,
    0x1.861ebfc37bcabp-1, 0x1.82c050f56cf6cp-1, 0x1.7f6ed4b20e2cep-1, 0x1.7c29a779c6855p-1,
    0x1.78f033ca0b0d8p-1, 0x1.75c1f0770d854p-1, 0x1.729e5f43f6d14p-1, 0x1.6f850baea7aecp-1,
    0x1.6c7589e635a8cp-1, 0x1.696f75e513b2cp-1, 0x1.667272a92e325p-1, 0x1.637e298550c19p-1,
    0x1.6092498802666p-1, 0x1.5dae86f4aff6ap-1, 0x1.5ad29acc85c89p-1, 0x1.57fe4264c8d8fp-1,
    0x1.55313f08d9e48p-1, 0x1.526b55a656cd5p-1, 0x1.4fac4e820b668p-1, 0x1.4cf3f4f494ec3p-1,
    0x1.4a42172dc5276p-1, 0x1.479685fdf5012p-1, 0x1.44f114a493676p-1, 0x1.425198a355fe3p-1,
    0x1.3fb7e99585b82p-1, 0x1.3d23e10af31a4p-1, 0x1.3a955a662cd0ep-1, 0x1.380c32bda00d8p-1,
    0x1.358848bf550f6p-1, 0x1.33097c9703a1bp-1, 0x1.308fafd643903p-1, 0x1.2e1ac55ea3c08p-1,
    0x1.2baaa14d7954ap-1, 0x1.293f28e93cd0bp-1, 0x1.26d84290504e8p-1, 0x1.2475d5a90db9bp-1,
    0x1.2217ca92ff7fbp-1, 0x1.1fbe0a9929608p-1, 0x1.1d687fe54997bp-1, 0x1.1b171573fd10dp-1,
    0x1.18c9b709b3c55p-1, 0x1.16805128639d5p-1, 0x1.143ad105ea9b6p-1, 0x1.11f9248311f50p-1,
    0x1.0fbb3a2325921p-1, 0x1.0d810104142b0p-1, 0x1.0b4a68d70d9b1p-1, 0x1.091761d995d79p-1,
    0x1.06e7dccf03c26p-1, 0x1.04bbcafa63f33p-1, 0x1.02931e18b8239p-1, 0x1.006dc85b8cacdp-1,
    0x1.fc9778c7bbd79p-2, 0x1.f859da7a900d9p-2, 0x1.f4229cb2f7afdp-2, 0x1.eff1a717e8f9fp-2,
    0x1.ebc6e20bd1f46p-2, 0x1.e7a236a4ec3d0p-2, 0x1.e3838ea5f9b87p-2, 0x1.df6ad477639dbp-2,
    0x1.db57f320b568fp-2, 0x1.d74ad6426de10p-2, 0x1.d3436a1021060p-2, 0x1.cf419b4ae5b94p-2,
    0x1.cb45573c0a83fp-2, 0x1.c74e8bb00d79ep-2, 0x1.c35d26f1d2ca0p-2, 0x1.bf7117c616a38p-2,
    0x1.bb8a4d6716d78p-2, 0x1.b7a8b780712fep-2, 0x1.b3cc462b331d2p-2, 0x1.aff4e9ea18554p-2,
    0x1.ac2293a5f5a74p-2, 0x1.a85534aa4d854p-2, 0x1.a48cbea20c04ap-2, 0x1.a0c9239468463p-2,
    0x1.9d0a55e1e93c0p-2, 0x1.995048418c0f3p-2, 0x1.959aedbe09fadp-2, 0x1.91ea39b33caeep-2,
    0x1.8e3e1fcb9f0efp-2, 0x1.8a9693fde9159p-2, 0x1.86f38a8ac5a8dp-2, 0x1.8354f7faa0de0p-2,
    0x1.7fbad11b8d917p-2, 0x1.7c250aff414a1p-2, 0x1.78939af9252f1p-2, 0x1.7506769c7b1dep-2,
    0x1.717d93ba96123p-2, 0x1.6df8e86124cbap-2, 0x1.6a786ad88de44p-2, 0x1.66fc11a25cbbcp-2,
    0x1.6383d377be515p-2, 0x1.600fa7480d29fp-2, 0x1.5c9f84376c23ep-2, 0x1.5933619d6ee95p-2,
    0x1.55cb3703d00e5p-2, 0x1.5266fc2533bd6p-2, 0x1.4f06a8ebf6db1p-2, 0x1.4baa357109cc3p-2,
    0x1.485199fad6ae1p-2, 0x1.44fccefc32524p-2, 0x1.41abcd1357a06p-2, 0x1.3e5e8d08ed2edp-2,
    0x1.3b1507cf143cep-2, 0x1.37cf368081386p-2, 0x1.348d125f9d1b8p-2, 0x1.314e94d5af610p-2,
    0x1.2e13b7721078cp-2, 0x1.2adc73e963ff8p-2, 0x1.27a8c414db0fdp-2, 0x1.2478a1f17de7fp-2,
    0x1.214c079f7cca1p-2, 0x1.1e22ef6188105p-2, 0x1.1afd539c2f071p-2, 0x1.17db2ed5454e7p-2,
    0x1.14bc7bb34ee8ep-2, 0x1.11a134fcf2443p-2, 0x1.0e895598709d8p-2, 0x1.0b74d88b242c2p-2,
    0x1.0863b8f904343p-2, 0x1.0555f2242e9b7p-2, 0x1.024b7f6c7748cp-2, 0x1.fe88b89df9410p-3,
    0x1.f88108cb8327ap-3, 0x1.f27fe6ce99907p-3, 0x1.ec854a4c99c8dp-3, 0x1.e6912b2283cf0p-3,
    0x1.e0a38164571adp-3, 0x1.dabc455c79021p-3, 0x1.d4db6f8b25179p-3, 0x1.cf00f8a5e7011p-3,
    0x1.c92cd9971df7dp-3, 0x1.c35f0b7d89d5cp-3, 0x1.bd9787abe18c2p-3, 0x1.b7d647a8731c0p-3,
    0x1.b21b452ccd13ep-3, 0x1.ac667a25717f3p-3, 0x1.a6b7e0b1926a4p-3, 0x1.a10f7322d7e50p-3,
    0x1.9b6d2bfd2fe7ap-3, 0x1.95d105f6a7c28p-3, 0x1.903afbf74fa74p-3, 0x1.8aab09192817dp-3,
    0x1.852128a819a81p-3, 0x1.7f9d5621f714ep-3, 0x1.7a1f8d368a2fap-3, 0x1.74a7c9c7ab5eap-3,
    0x1.6f3607e96472fp-3, 0x1.69ca43e21f293p-3, 0x1.64647a2adf17dp-3, 0x1.5f04a76f883d0p-3,
    0x1.59aac88f31d96p-3, 0x1.5456da9c86870p-3, 0x1.4f08dade31fbfp-3, 0x1.49c0c6cf5ce55p-3,
    0x1.447e9c20375c2p-3, 0x1.3f4258b6931ecp-3, 0x1.3a0bfaae8d81fp-3, 0x1.34db805b4ab77p-3,
    0x1.2fb0e847c2a43p-3, 0x1.2a8c3137a073bp-3, 0x1.256d5a2835eb0p-3, 0x1.2054625183c12p-3,
    0x1.1b41492757d2ep-3, 0x1.16340e5a82d5ep-3, 0x1.112cb1da26eadp-3, 0x1.0c2b33d5209e0p-3,
    0x1.072f94bb8bfaap-3, 0x1.0239d54067d1ep-3, 0x1.fa93ecb6b2244p-4, 0x1.f0bff29520e3bp-4,
    0x1.e6f7bf29aa56ap-4, 0x1.dd3b56176e8c0p-4, 0x1.d38abb9bd9226p-4, 0x1.c9e5f493b7423p-4,
    0x1.c04d0680b0fddp-4, 0x1.b6bff78f2e25cp-4, 0x1.ad3ece9caf65ep-4, 0x1.a3c9933ea6248p-4,
    0x1.9a604dc9d5afcp-4, 0x1.9103075a4a076p-4, 0x1.87b1c9dbf2830p-4, 0x1.7e6ca013eeff7p-4,
    0x1.753395aaa117bp-4, 0x1.6c06b73694a13p-4, 0x1.62e6124854d1dp-4, 0x1.59d1b577466a4p-4,
    0x1.50c9b06fa2bb9p-4, 0x1.47ce1401b2209p-4, 0x1.3edef23269a65p-4, 0x1.35fc5e4d93e81p-4,
    0x1.2d266cf9b3126p-4, 0x1.245d344dd0dbap-4, 0x1.1ba0cbe978991p-4, 0x1.12f14d0f217bbp-4,
    0x1.0a4ed2c159612p-4, 0x1.01b979e30e4c7p-4, 0x1.f262c2b6c6e49p-5, 0x1.e16d547b251f6p-5,
    0x1.d092efeadf12cp-5, 0x1.bfd3e0f282a25p-5, 0x1.af30790385f30p-5, 0x1.9ea90f92955aap-5,
    0x1.8e3e02a68b5ffp-5, 0x1.7defb77af2751p-5, 0x1.6dbe9b398d030p-5, 0x1.5dab23cf2ae13p-5,
    0x1.4db5d0e112799p-5, 0x1.3ddf2ce98eef0p-5, 0x1.2e27ce83df4c9p-5, 0x1.1e9059f1f6a89p-5,
    0x1.0f1982e968037p-5, 0x1.ff881d718a5f8p-6, 0x1.e121adb828cb1p-6, 0x1.c301983cd0980p-6,
    0x1.a529f4e22ec26p-6, 0x1.879d1b600c125p-6, 0x1.6a5daf40bbf44p-6, 0x1.4d6eaf2fbb038p-6,
    0x1.30d388dab5e4ap-6, 0x1.1490334603057p-6, 0x1.f152a4f72dd8fp-7, 0x1.ba48d274f8f82p-7,
    0x1.841040d8da4bbp-7, 0x1.4eb96421ad029p-7, 0x1.1a59229952fc7p-7, 0x1.ce160f8ec684dp-8,
    0x1.69ea8d90cb884p-8, 0x1.08a1f03b0b1bfp-8, 0x1.55f9f43c1b08cp-9, 0x1.4a605b6b9f6f0p-10,
    0x1.f4a946f1383a9p-12,
};

} // namespace random_detail

} // namespace keel
