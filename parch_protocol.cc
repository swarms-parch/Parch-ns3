// Matches the protocol flow in the current PARCH paper:
//   1) GCS-CH rolling PUF-bound authentication (M0, M1, M2)
//   2) Failure-resilient ACC handover (M3, M4) without ACC_old participation
//
// Crypto libraries: OpenSSL 3.x and liboqs (ML-KEM-512).
// PUF behavior is emulated because ns-3 has no physical PUF device.
// Cryptographic execution time is NOT taken from this simulation; the paper
// reports separate Raspberry Pi 5 primitive benchmarks.

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace ns3;

namespace parch {

using Bytes = std::vector<uint8_t>;

static void Append(Bytes& dst, const Bytes& src)
{
    dst.insert(dst.end(), src.begin(), src.end());
}

static void AppendString(Bytes& dst, const std::string& s)
{
    dst.insert(dst.end(), s.begin(), s.end());
}

static void AppendU16(Bytes& dst, uint16_t v)
{
    dst.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    dst.push_back(static_cast<uint8_t>(v & 0xff));
}

static void AppendU32(Bytes& dst, uint32_t v)
{
    dst.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    dst.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    dst.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    dst.push_back(static_cast<uint8_t>(v & 0xff));
}

static uint16_t ReadU16(const Bytes& src, size_t& off)
{
    if (off + 2 > src.size())
        throw std::runtime_error("ReadU16 overflow");
    uint16_t v = (static_cast<uint16_t>(src[off]) << 8) |
                 static_cast<uint16_t>(src[off + 1]);
    off += 2;
    return v;
}

static uint32_t ReadU32(const Bytes& src, size_t& off)
{
    if (off + 4 > src.size())
        throw std::runtime_error("ReadU32 overflow");
    uint32_t v = (static_cast<uint32_t>(src[off]) << 24) |
                 (static_cast<uint32_t>(src[off + 1]) << 16) |
                 (static_cast<uint32_t>(src[off + 2]) << 8) |
                 static_cast<uint32_t>(src[off + 3]);
    off += 4;
    return v;
}

static Bytes ReadBytes(const Bytes& src, size_t& off, size_t n)
{
    if (off + n > src.size())
        throw std::runtime_error("ReadBytes overflow");
    Bytes out(src.begin() + static_cast<long>(off),
              src.begin() + static_cast<long>(off + n));
    off += n;
    return out;
}

static Bytes Xor(const Bytes& a, const Bytes& b)
{
    if (a.size() != b.size())
        throw std::runtime_error("XOR size mismatch");
    Bytes out(a.size());
    for (size_t i = 0; i < a.size(); ++i)
        out[i] = a[i] ^ b[i];
    return out;
}

static Bytes RandomBytes(size_t n)
{
    Bytes out(n);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return out;
}

static bool CtEqual(const Bytes& a, const Bytes& b)
{
    return a.size() == b.size() &&
           CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

static std::string HexShort(const Bytes& b, size_t shown = 6)
{
    std::ostringstream oss;
    size_t n = std::min(shown, b.size());
    for (size_t i = 0; i < n; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(b[i]);
    if (b.size() > n)
        oss << "...";
    return oss.str();
}

static Bytes Digest(const EVP_MD* md, const Bytes& in)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    unsigned int outLen = EVP_MD_get_size(md);
    Bytes out(outLen);
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, in.data(), in.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, out.data(), &outLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Digest failed");
    }
    EVP_MD_CTX_free(ctx);
    out.resize(outLen);
    return out;
}

static Bytes Sha256(const Bytes& in)
{
    return Digest(EVP_sha256(), in);
}

static Bytes HmacSha256(const Bytes& key, const Bytes& data)
{
    unsigned int len = 0;
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned char* p = HMAC(EVP_sha256(),
                            key.data(),
                            static_cast<int>(key.size()),
                            data.data(),
                            data.size(),
                            out.data(),
                            &len);
    if (!p)
        throw std::runtime_error("HMAC failed");
    out.resize(len);
    return out;
}

static Bytes Trunc(const Bytes& in, size_t n)
{
    if (in.size() < n)
        throw std::runtime_error("Trunc input too short");
    return Bytes(in.begin(), in.begin() + static_cast<long>(n));
}

// BLAKE2b with an actual 36-byte digest parameter (288 bits), as used by PARCH.
static uint64_t Rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

static uint64_t Load64(const uint8_t* p)
{
    uint64_t w = 0;
    for (unsigned i = 0; i < 8; ++i)
        w |= static_cast<uint64_t>(p[i]) << (8 * i);
    return w;
}

static void Store64(uint8_t* p, uint64_t w)
{
    for (unsigned i = 0; i < 8; ++i)
        p[i] = static_cast<uint8_t>((w >> (8 * i)) & 0xff);
}

static void Blake2bCompress(std::array<uint64_t, 8>& h,
                            const uint8_t block[128],
                            uint64_t t0,
                            uint64_t t1,
                            bool last)
{
    static constexpr uint64_t IV[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    static constexpr uint8_t SIGMA[12][16] = {
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}};

    uint64_t m[16];
    for (unsigned i = 0; i < 16; ++i)
        m[i] = Load64(block + 8 * i);

    uint64_t v[16];
    for (unsigned i = 0; i < 8; ++i)
    {
        v[i] = h[i];
        v[i + 8] = IV[i];
    }
    v[12] ^= t0;
    v[13] ^= t1;
    if (last)
        v[14] = ~v[14];

    auto G = [&](unsigned a, unsigned b, unsigned c, unsigned d,
                 uint64_t x, uint64_t y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Rotr64(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Rotr64(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Rotr64(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Rotr64(v[b] ^ v[c], 63);
    };

    for (unsigned r = 0; r < 12; ++r)
    {
        const uint8_t* s = SIGMA[r];
        G(0,4,8,12,m[s[0]],m[s[1]]);
        G(1,5,9,13,m[s[2]],m[s[3]]);
        G(2,6,10,14,m[s[4]],m[s[5]]);
        G(3,7,11,15,m[s[6]],m[s[7]]);
        G(0,5,10,15,m[s[8]],m[s[9]]);
        G(1,6,11,12,m[s[10]],m[s[11]]);
        G(2,7,8,13,m[s[12]],m[s[13]]);
        G(3,4,9,14,m[s[14]],m[s[15]]);
    }

    for (unsigned i = 0; i < 8; ++i)
        h[i] ^= v[i] ^ v[i + 8];
}

static Bytes Blake2b36(const Bytes& in)
{
    static constexpr uint64_t IV[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    std::array<uint64_t, 8> h{};
    for (unsigned i = 0; i < 8; ++i)
        h[i] = IV[i];
    h[0] ^= 0x01010000ULL ^ 36ULL;

    uint64_t t0 = 0;
    uint64_t t1 = 0;
    size_t off = 0;

    while (in.size() - off > 128)
    {
        uint8_t block[128];
        std::memcpy(block, in.data() + off, 128);
        uint64_t old = t0;
        t0 += 128;
        if (t0 < old)
            ++t1;
        Blake2bCompress(h, block, t0, t1, false);
        off += 128;
    }

    uint8_t last[128]{};
    size_t remaining = in.size() - off;
    if (remaining > 0)
        std::memcpy(last, in.data() + off, remaining);
    uint64_t old = t0;
    t0 += static_cast<uint64_t>(remaining);
    if (t0 < old)
        ++t1;
    Blake2bCompress(h, last, t0, t1, true);

    Bytes full(64);
    for (unsigned i = 0; i < 8; ++i)
        Store64(full.data() + 8 * i, h[i]);
    full.resize(36);
    return full;
}

class PufDevice
{
  public:
    explicit PufDevice(double bitErrorRate)
        : m_secret(RandomBytes(32)), m_errorRate(bitErrorRate)
    {
    }

    Bytes Evaluate(const Bytes& challenge) const
    {
        Bytes base = HmacSha256(m_secret, challenge);
        if (m_errorRate <= 0.0)
            return base;

        Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
        for (size_t i = 0; i < base.size(); ++i)
        {
            for (unsigned bit = 0; bit < 8; ++bit)
            {
                if (uv->GetValue(0.0, 1.0) < m_errorRate)
                    base[i] ^= static_cast<uint8_t>(1u << bit);
            }
        }
        return base;
    }

  private:
    Bytes m_secret;
    double m_errorRate;
};

struct FeOutput
{
    Bytes stable;
    Bytes helper;
};

class FuzzyExtractor
{
  private:
    static bool GetBit(const Bytes& b, size_t pos)
    {
        return ((b[pos / 8] >> (7 - (pos % 8))) & 1u) != 0;
    }

    static void SetBit(Bytes& b, size_t pos, bool v)
    {
        uint8_t mask = static_cast<uint8_t>(1u << (7 - (pos % 8)));
        if (v)
            b[pos / 8] |= mask;
        else
            b[pos / 8] &= static_cast<uint8_t>(~mask);
    }

    static Bytes EncodeHamming74(const Bytes& secret18)
    {
        if (secret18.size() != 18)
            throw std::runtime_error("FE secret must be 18 bytes");

        Bytes code(32, 0);
        size_t outBit = 0;
        for (size_t nib = 0; nib < 36; ++nib)
        {
            uint8_t byte = secret18[nib / 2];
            uint8_t n = (nib % 2 == 0) ? static_cast<uint8_t>((byte >> 4) & 0x0f)
                                       : static_cast<uint8_t>(byte & 0x0f);
            bool d1 = (n >> 3) & 1;
            bool d2 = (n >> 2) & 1;
            bool d3 = (n >> 1) & 1;
            bool d4 = n & 1;
            bool p1 = d1 ^ d2 ^ d4;
            bool p2 = d1 ^ d3 ^ d4;
            bool p4 = d2 ^ d3 ^ d4;
            bool cw[7] = {p1, p2, d1, p4, d2, d3, d4};
            for (bool bit : cw)
                SetBit(code, outBit++, bit);
        }
        return code;
    }

    static Bytes DecodeHamming74(Bytes code)
    {
        Bytes secret(18, 0);
        size_t inBit = 0;
        for (size_t nib = 0; nib < 36; ++nib)
        {
            bool b[8]{};
            for (int j = 1; j <= 7; ++j)
                b[j] = GetBit(code, inBit++);

            int s1 = b[1] ^ b[3] ^ b[5] ^ b[7];
            int s2 = b[2] ^ b[3] ^ b[6] ^ b[7];
            int s4 = b[4] ^ b[5] ^ b[6] ^ b[7];
            int err = s1 + 2 * s2 + 4 * s4;
            if (err >= 1 && err <= 7)
                b[err] = !b[err];

            uint8_t n = static_cast<uint8_t>((b[3] << 3) |
                                             (b[5] << 2) |
                                             (b[6] << 1) |
                                             b[7]);
            if (nib % 2 == 0)
                secret[nib / 2] = static_cast<uint8_t>(n << 4);
            else
                secret[nib / 2] |= n;
        }
        return secret;
    }

  public:
    static FeOutput Gen(const Bytes& raw)
    {
        if (raw.size() != 32)
            throw std::runtime_error("FE raw PUF response must be 32 bytes");
        Bytes secret18 = RandomBytes(18);
        Bytes code = EncodeHamming74(secret18);
        FeOutput out;
        out.helper = Xor(raw, code);
        out.stable = Sha256(secret18);
        return out;
    }

    static Bytes Rep(const Bytes& noisyRaw, const Bytes& helper)
    {
        if (noisyRaw.size() != 32 || helper.size() != 32)
            throw std::runtime_error("FE Rep size mismatch");
        Bytes noisyCode = Xor(noisyRaw, helper);
        Bytes secret18 = DecodeHamming74(noisyCode);
        return Sha256(secret18);
    }
};

// Functional WOTS+ implementation with the paper's n=16, w=16 parameters.
// Performance numbers in the paper come from the separate SPHINCS+ benchmark.
class WotsPlus
{
  public:
    static constexpr size_t N = 16;
    static constexpr uint8_t W = 16;
    static constexpr size_t LEN1 = 32;
    static constexpr size_t LEN2 = 3;
    static constexpr size_t LEN = LEN1 + LEN2;
    static constexpr size_t SIG_LEN = LEN * N;

    static Bytes PublicKey(const Bytes& seed)
    {
        Bytes all;
        all.reserve(LEN * N);
        for (size_t i = 0; i < LEN; ++i)
        {
            Bytes sk = SecretElement(seed, static_cast<uint16_t>(i));
            Bytes pkElem = Chain(sk, static_cast<uint16_t>(i), 0, W - 1);
            Append(all, pkElem);
        }
        Bytes d;
        AppendString(d, "WOTS-PK");
        Append(d, all);
        return Trunc(Sha256(d), N);
    }

    static Bytes Sign(const Bytes& seed, const Bytes& digest32)
    {
        std::vector<uint8_t> digits = BaseW(digest32);
        Bytes sig;
        sig.reserve(SIG_LEN);
        for (size_t i = 0; i < LEN; ++i)
        {
            Bytes sk = SecretElement(seed, static_cast<uint16_t>(i));
            Bytes s = Chain(sk, static_cast<uint16_t>(i), 0, digits[i]);
            Append(sig, s);
        }
        return sig;
    }

    static Bytes RecoverPublicKey(const Bytes& signature, const Bytes& digest32)
    {
        if (signature.size() != SIG_LEN)
            throw std::runtime_error("Invalid WOTS+ signature length");
        std::vector<uint8_t> digits = BaseW(digest32);
        Bytes all;
        all.reserve(LEN * N);
        for (size_t i = 0; i < LEN; ++i)
        {
            Bytes s(signature.begin() + static_cast<long>(i * N),
                    signature.begin() + static_cast<long>((i + 1) * N));
            Bytes pkElem = Chain(s,
                                 static_cast<uint16_t>(i),
                                 digits[i],
                                 static_cast<uint8_t>((W - 1) - digits[i]));
            Append(all, pkElem);
        }
        Bytes d;
        AppendString(d, "WOTS-PK");
        Append(d, all);
        return Trunc(Sha256(d), N);
    }

  private:
    static Bytes SecretElement(const Bytes& seed, uint16_t idx)
    {
        Bytes d;
        AppendString(d, "WOTS-SK");
        Append(d, seed);
        AppendU16(d, idx);
        return Trunc(Sha256(d), N);
    }

    static Bytes Chain(Bytes x, uint16_t idx, uint8_t start, uint8_t steps)
    {
        for (uint8_t s = start; s < static_cast<uint8_t>(start + steps); ++s)
        {
            Bytes d;
            AppendString(d, "WOTS-F");
            AppendU16(d, idx);
            d.push_back(s);
            Append(d, x);
            x = Trunc(Sha256(d), N);
        }
        return x;
    }

    static std::vector<uint8_t> BaseW(const Bytes& digest32)
    {
        Bytes m = Trunc(digest32, N);
        std::vector<uint8_t> out;
        out.reserve(LEN);
        for (uint8_t b : m)
        {
            out.push_back(static_cast<uint8_t>((b >> 4) & 0x0f));
            out.push_back(static_cast<uint8_t>(b & 0x0f));
        }
        uint16_t csum = 0;
        for (uint8_t d : out)
            csum += static_cast<uint16_t>((W - 1) - d);
        out.push_back(static_cast<uint8_t>((csum >> 8) & 0x0f));
        out.push_back(static_cast<uint8_t>((csum >> 4) & 0x0f));
        out.push_back(static_cast<uint8_t>(csum & 0x0f));
        return out;
    }
};

struct MerkleStep
{
    Bytes sibling;
    bool siblingIsLeft{false};
};
using MerkleProof = std::vector<MerkleStep>;

static Bytes HashPair(const Bytes& left, const Bytes& right)
{
    Bytes d;
    Append(d, left);
    Append(d, right);
    return Sha256(d);
}

class MerkleTree
{
  public:
    explicit MerkleTree(std::vector<Bytes> leaves)
    {
        if (leaves.empty())
            throw std::runtime_error("Merkle tree needs at least one leaf");
        m_levels.push_back(std::move(leaves));
        while (m_levels.back().size() > 1)
        {
            const auto& cur = m_levels.back();
            std::vector<Bytes> next;
            for (size_t i = 0; i < cur.size(); i += 2)
            {
                const Bytes& left = cur[i];
                const Bytes& right = (i + 1 < cur.size()) ? cur[i + 1] : cur[i];
                next.push_back(HashPair(left, right));
            }
            m_levels.push_back(std::move(next));
        }
    }

    Bytes Root() const
    {
        return m_levels.back().front();
    }

    MerkleProof Proof(size_t index) const
    {
        if (index >= m_levels.front().size())
            throw std::runtime_error("Merkle proof index out of range");
        MerkleProof proof;
        size_t idx = index;
        for (size_t level = 0; level + 1 < m_levels.size(); ++level)
        {
            const auto& cur = m_levels[level];
            size_t siblingIdx = (idx % 2 == 0) ? idx + 1 : idx - 1;
            if (siblingIdx >= cur.size())
                siblingIdx = idx;
            proof.push_back({cur[siblingIdx], siblingIdx < idx});
            idx /= 2;
        }
        return proof;
    }

    static bool Verify(const Bytes& leaf, const MerkleProof& proof, const Bytes& root)
    {
        Bytes cur = leaf;
        for (const auto& step : proof)
            cur = step.siblingIsLeft ? HashPair(step.sibling, cur)
                                     : HashPair(cur, step.sibling);
        return CtEqual(cur, root);
    }

  private:
    std::vector<std::vector<Bytes>> m_levels;
};

struct AccPublicEnrollment
{
    Bytes pid;                       // 32-bit PID_A
    Bytes root;                      // W_A
    std::vector<MerkleProof> proofs;
};

struct ChPublicEnrollment
{
    Bytes pidH;                      // 32-bit PID_i^H
    Bytes chId;                      // 32-bit CH_i identifier
    Bytes challengeH;                // one C_i^H for this CH
    Bytes globalRootY;               // Y
    std::vector<MerkleProof> lower;  // L_i,v -> Z_i
    MerkleProof upper;               // Z_i -> Y
};

struct PermissionedLedger
{
    AccPublicEnrollment accNew;
    ChPublicEnrollment ch;
};

struct LightweightChState
{
    Bytes pid;
    Bytes helper;
    Bytes sessionKey;
};

struct LightweightGcsState
{
    Bytes challenge;
    Bytes response;
    Bytes pid;
    Bytes sessionKey;
};

struct ChHandoverState
{
    Bytes pidH;
    Bytes chId;
    Bytes helperH;                   // one HD_i^H
    std::set<uint16_t> usedV;
    std::set<uint16_t> usedU;
    Bytes sessionKey;
    uint32_t epoch{1};
};

struct AccSecretState
{
    Bytes pid;
    Bytes masterSeed;
    std::set<uint16_t> usedU;
    uint32_t epoch{1};
};

struct SharedSystem
{
    explicit SharedSystem(double pufErrorRate)
        : puf(std::make_shared<PufDevice>(pufErrorRate))
    {
    }

    std::shared_ptr<PufDevice> puf;
    PermissionedLedger ledger;
    LightweightChState lightCh;
    LightweightGcsState lightGcs;
    ChHandoverState chHo;
    AccSecretState newAcc;
    Bytes oldAccPid;
    bool oldAccAvailable{true};
    size_t credentialCount{1024};
    size_t enrolledChCount{10};
};

static Bytes HandoverMasterSeed(const Bytes& stableR, const Bytes& pidH)
{
    Bytes d;
    Append(d, stableR);
    Append(d, pidH);
    return Sha256(d);
}

static Bytes ChCredentialSeed(const Bytes& masterSeed, uint16_t idx)
{
    Bytes d;
    Append(d, masterSeed);
    AppendU16(d, idx);
    return Sha256(d);
}

static Bytes AccCredentialSeed(const AccSecretState& acc, uint16_t idx)
{
    Bytes d;
    Append(d, acc.masterSeed);
    Append(d, acc.pid);
    AppendU16(d, idx);
    return Sha256(d);
}

static Bytes MakeAccLeaf(const Bytes& pid, uint16_t u, const Bytes& wotsPk)
{
    Bytes d;
    Append(d, pid);
    AppendU16(d, u);
    Append(d, wotsPk);
    return Sha256(d);
}

static Bytes MakeChLeaf(const Bytes& pidH,
                        uint16_t v,
                        const Bytes& chId,
                        const Bytes& wotsPk)
{
    Bytes d;
    Append(d, pidH);
    AppendU16(d, v);
    Append(d, chId);
    Append(d, wotsPk);
    return Sha256(d);
}

static AccPublicEnrollment EnrollAcc(AccSecretState& acc, size_t m)
{
    acc.pid = RandomBytes(4);
    acc.masterSeed = RandomBytes(32);

    std::vector<Bytes> leaves;
    leaves.reserve(m);
    for (uint32_t ui = 1; ui <= m; ++ui)
    {
        uint16_t u = static_cast<uint16_t>(ui);
        Bytes seed = AccCredentialSeed(acc, u);
        Bytes pk = WotsPlus::PublicKey(seed);
        leaves.push_back(MakeAccLeaf(acc.pid, u, pk));
    }

    MerkleTree tree(leaves);
    AccPublicEnrollment pub;
    pub.pid = acc.pid;
    pub.root = tree.Root();
    for (size_t pos = 0; pos < m; ++pos)
        pub.proofs.push_back(tree.Proof(pos));
    return pub;
}

static void EnrollSystem(const std::shared_ptr<SharedSystem>& s)
{
    // GCS-CH rolling authentication enrollment.
    Bytes cG = RandomBytes(4);
    FeOutput feG = FuzzyExtractor::Gen(s->puf->Evaluate(cG));
    Bytes pidG = RandomBytes(4);

    s->lightCh.pid = pidG;
    s->lightCh.helper = feG.helper;
    s->lightGcs.challenge = cG;
    s->lightGcs.response = feG.stable;
    s->lightGcs.pid = pidG;

    // ACC_new enrollment.
    s->ledger.accNew = EnrollAcc(s->newAcc, s->credentialCount);

    // The current/old ACC PID is mission context only; it contributes no secret
    // material to the failure-resilient handover.
    s->oldAccPid = RandomBytes(4);

    // One handover PUF CRP for the active CH.
    s->chHo.pidH = RandomBytes(4);
    s->chHo.chId = RandomBytes(4);
    Bytes cH = RandomBytes(4);
    FeOutput feH = FuzzyExtractor::Gen(s->puf->Evaluate(cH));
    s->chHo.helperH = feH.helper;

    Bytes masterH = HandoverMasterSeed(feH.stable, s->chHo.pidH);
    std::vector<Bytes> leaves;
    leaves.reserve(s->credentialCount);
    for (uint32_t vi = 1; vi <= s->credentialCount; ++vi)
    {
        uint16_t v = static_cast<uint16_t>(vi);
        Bytes seed = ChCredentialSeed(masterH, v);
        Bytes pk = WotsPlus::PublicKey(seed);
        leaves.push_back(MakeChLeaf(s->chHo.pidH, v, s->chHo.chId, pk));
    }

    MerkleTree lowerTree(leaves);
    Bytes zi = lowerTree.Root();

    // One CH participates in the packet-level run. Additional enrolled roots are
    // included so the upper tree uses the same n=10 structure as the evaluation.
    std::vector<Bytes> upperLeaves;
    upperLeaves.reserve(s->enrolledChCount);
    upperLeaves.push_back(zi);
    for (size_t i = 1; i < s->enrolledChCount; ++i)
        upperLeaves.push_back(Sha256(RandomBytes(32)));
    MerkleTree upperTree(upperLeaves);

    s->ledger.ch.pidH = s->chHo.pidH;
    s->ledger.ch.chId = s->chHo.chId;
    s->ledger.ch.challengeH = cH;
    s->ledger.ch.globalRootY = upperTree.Root();
    s->ledger.ch.upper = upperTree.Proof(0);
    for (size_t pos = 0; pos < s->credentialCount; ++pos)
        s->ledger.ch.lower.push_back(lowerTree.Proof(pos));

    std::cout << "[Enrollment complete]\n"
              << "  GCS-CH rolling PID : " << HexShort(s->lightCh.pid) << "\n"
              << "  CH handover PID    : " << HexShort(s->chHo.pidH) << "\n"
              << "  ACC_old PID        : " << HexShort(s->oldAccPid) << "\n"
              << "  ACC_new PID        : " << HexShort(s->newAcc.pid) << "\n"
              << "  ACC root W_A       : " << HexShort(s->ledger.accNew.root) << "\n"
              << "  CH global root Y   : " << HexShort(s->ledger.ch.globalRootY) << "\n\n";
}

enum MessageType : uint8_t
{
    AUTH_M0 = 1,
    AUTH_M1 = 2,
    AUTH_M2 = 3,
    HO_M3 = 4,
    HO_M4 = 5
};

static Bytes MakeCtxH(const Bytes& pidOld, const Bytes& pidNew, uint32_t epochNext)
{
    Bytes d;
    Append(d, pidOld);
    Append(d, pidNew);
    AppendU32(d, epochNext);
    return d;
}

static Bytes MakeDa(const Bytes& ctxH,
                    uint16_t u,
                    uint32_t timestampA,
                    const Bytes& nonceA,
                    const Bytes& pkK)
{
    Bytes d;
    Append(d, ctxH);
    AppendU16(d, u);
    AppendU32(d, timestampA);
    Append(d, nonceA);
    Append(d, Sha256(pkK));
    return Sha256(d);
}

static Bytes MakeCtxI(const Bytes& ctxH,
                      const Bytes& pidH,
                      const Bytes& nonceA,
                      const Bytes& nonceI,
                      const Bytes& pkK,
                      const Bytes& ct)
{
    Bytes d;
    Append(d, ctxH);
    Append(d, pidH);
    Append(d, nonceA);
    Append(d, nonceI);
    Append(d, Sha256(pkK));
    Append(d, Sha256(ct));
    return Sha256(d);
}

static Bytes MakeSessionKey(const Bytes& kemShared, const Bytes& ctxI)
{
    Bytes d;
    Append(d, kemShared);
    Append(d, ctxI);
    return Sha256(d);
}

static Bytes MakeDi(const Bytes& ctxI, uint16_t v)
{
    Bytes d;
    Append(d, ctxI);
    AppendU16(d, v);
    return Sha256(d);
}

static Bytes MakeTau(const Bytes& sessionKey, const Bytes& ctxI)
{
    return HmacSha256(sessionKey, ctxI);
}

class ParchApp : public Application
{
  public:
    enum Role
    {
        GCS,
        CH,
        ACC_OLD,
        ACC_NEW
    };

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("parch::ParchApp")
                                .SetParent<Application>()
                                .SetGroupName("Applications")
                                .AddConstructor<ParchApp>();
        return tid;
    }

    ParchApp() = default;

    void Configure(Role role,
                   std::shared_ptr<SharedSystem> system,
                   uint16_t port,
                   uint32_t freshnessWindowMs)
    {
        m_role = role;
        m_system = std::move(system);
        m_port = port;
        m_freshnessWindowMs = freshnessWindowMs;

        if ((m_role == CH || m_role == ACC_NEW) && !m_kem)
        {
            m_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
            if (!m_kem)
                throw std::runtime_error("ML-KEM-512 not available in liboqs");
        }
    }

    ~ParchApp() override
    {
        if (m_kem)
            OQS_KEM_free(m_kem);
    }

    void SetPeers(Ipv4Address gcs,
                  Ipv4Address ch,
                  Ipv4Address oldAcc,
                  Ipv4Address newAcc)
    {
        m_gcsAddr = gcs;
        m_chAddr = ch;
        m_oldAddr = oldAcc;
        m_newAddr = newAcc;
    }

    void StartInitialAuthentication()
    {
        if (m_role != CH)
            return;

        m_initiator = RandomBytes(4);
        Bytes msg;
        msg.push_back(AUTH_M0);
        Append(msg, m_initiator);

        std::cout << "\n" << TimeNow() << " CH -> GCS : M0\n";
        Send(msg, m_gcsAddr);
    }

    void FailOldAcc()
    {
        if (m_role != ACC_OLD)
            return;
        m_available = false;
        m_system->oldAccAvailable = false;
        std::cout << "\n" << TimeNow()
                  << " *** ACC_old becomes unavailable ***\n";
    }

    void StartHandover()
    {
        if (m_role != ACC_NEW)
            return;

        uint16_t u = NextUnused(m_system->newAcc.usedU,
                                m_system->credentialCount);
        m_system->newAcc.usedU.insert(u);
        m_pendingU = u;
        m_pendingEpoch = m_system->newAcc.epoch + 1;
        m_timestampA = static_cast<uint32_t>(Simulator::Now().GetMilliSeconds());
        m_nonceA = RandomBytes(32);

        m_kemPk.resize(m_kem->length_public_key);
        m_kemSk.resize(m_kem->length_secret_key);
        if (OQS_KEM_keypair(m_kem, m_kemPk.data(), m_kemSk.data()) != OQS_SUCCESS)
            throw std::runtime_error("ML-KEM keypair failed");

        Bytes ctxH = MakeCtxH(m_system->oldAccPid,
                              m_system->newAcc.pid,
                              m_pendingEpoch);
        Bytes dA = MakeDa(ctxH,
                          u,
                          m_timestampA,
                          m_nonceA,
                          m_kemPk);
        Bytes seed = AccCredentialSeed(m_system->newAcc, u);
        Bytes sigA = WotsPlus::Sign(seed, dA);

        Bytes msg;
        msg.push_back(HO_M3);
        Append(msg, m_system->newAcc.pid);
        AppendU32(msg, m_pendingEpoch);
        AppendU16(msg, u);
        AppendU32(msg, m_timestampA);
        Append(msg, m_nonceA);
        Append(msg, m_kemPk);
        Append(msg, sigA);

        std::cout << "\n" << TimeNow()
                  << " ACC_new -> CH : M3  [ACC authentication]\n";
        Send(msg, m_chAddr);
    }

  private:
    void StartApplication() override
    {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
        if (m_socket->Bind(local) < 0)
            throw std::runtime_error("Socket bind failed");
        m_socket->SetRecvCallback(MakeCallback(&ParchApp::Receive, this));
    }

    void StopApplication() override
    {
        if (m_socket)
        {
            m_socket->Close();
            m_socket = nullptr;
        }
    }

    void Send(const Bytes& data, Ipv4Address dst)
    {
        Ptr<Packet> p = Create<Packet>(data.data(), static_cast<uint32_t>(data.size()));
        int sent = m_socket->SendTo(p, 0, InetSocketAddress(dst, m_port));
        if (sent < 0)
            std::cerr << TimeNow() << " ERROR: UDP send failed to " << dst << "\n";
    }

    void Receive(Ptr<Socket> socket)
    {
        Address from;
        while (Ptr<Packet> packet = socket->RecvFrom(from))
        {
            if (!m_available && m_role == ACC_OLD)
                continue;

            Bytes data(packet->GetSize());
            packet->CopyData(data.data(), data.size());
            if (data.empty())
                continue;

            try
            {
                switch (data[0])
                {
                case AUTH_M0:
                    if (m_role == GCS)
                        HandleAuthM0(data);
                    break;
                case AUTH_M1:
                    if (m_role == CH)
                        HandleAuthM1(data);
                    break;
                case AUTH_M2:
                    if (m_role == GCS)
                        HandleAuthM2(data);
                    break;
                case HO_M3:
                    if (m_role == CH)
                        HandleHandoverM3(data);
                    break;
                case HO_M4:
                    if (m_role == ACC_NEW)
                        HandleHandoverM4(data);
                    break;
                default:
                    std::cerr << TimeNow() << " Unknown message type\n";
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << TimeNow() << " protocol error: " << e.what() << "\n";
            }
        }
    }

    void HandleAuthM0(const Bytes& data)
    {
        size_t off = 1;
        m_initiator = ReadBytes(data, off, 4);
        if (off != data.size())
            throw std::runtime_error("M0 trailing bytes");

        auto& st = m_system->lightGcs;
        m_q = RandomBytes(32);
        m_cNew = RandomBytes(4);
        Bytes maskedQ = Xor(st.response, m_q);

        Bytes tagInput;
        Append(tagInput, st.response);
        Append(tagInput, m_q);
        Append(tagInput, st.challenge);
        Append(tagInput, m_cNew);
        Append(tagInput, m_initiator);
        Bytes tau1 = Sha256(tagInput);

        Bytes msg;
        msg.push_back(AUTH_M1);
        Append(msg, maskedQ);
        Append(msg, st.challenge);
        Append(msg, m_cNew);
        Append(msg, tau1);

        std::cout << TimeNow() << " GCS -> CH : M1\n";
        Send(msg, m_chAddr);
    }

    void HandleAuthM1(const Bytes& data)
    {
        size_t off = 1;
        Bytes maskedQ = ReadBytes(data, off, 32);
        Bytes cCurrent = ReadBytes(data, off, 4);
        Bytes cNew = ReadBytes(data, off, 4);
        Bytes tau1 = ReadBytes(data, off, 32);
        if (off != data.size())
            throw std::runtime_error("M1 trailing bytes");

        Bytes rCurrent = FuzzyExtractor::Rep(
            m_system->puf->Evaluate(cCurrent),
            m_system->lightCh.helper);
        Bytes q = Xor(maskedQ, rCurrent);

        Bytes tagInput;
        Append(tagInput, rCurrent);
        Append(tagInput, q);
        Append(tagInput, cCurrent);
        Append(tagInput, cNew);
        Append(tagInput, m_initiator);
        if (!CtEqual(tau1, Sha256(tagInput)))
            throw std::runtime_error("CH rejected M1");

        FeOutput feNew = FuzzyExtractor::Gen(m_system->puf->Evaluate(cNew));
        Bytes v = Blake2b36(q);
        Bytes n(v.begin(), v.begin() + 32);
        Bytes pidNew(v.begin() + 32, v.begin() + 36);
        Bytes maskedRNew = Xor(feNew.stable, n);

        Bytes tag2Input;
        Append(tag2Input, cNew);
        Append(tag2Input, q);
        Append(tag2Input, n);
        Append(tag2Input, feNew.stable);
        Bytes tau2 = Sha256(tag2Input);

        Bytes pidOld = m_system->lightCh.pid;
        m_system->lightCh.sessionKey = n;
        m_system->lightCh.pid = pidNew;
        m_system->lightCh.helper = feNew.helper;

        Bytes msg;
        msg.push_back(AUTH_M2);
        Append(msg, pidOld);
        Append(msg, maskedRNew);
        Append(msg, tau2);

        std::cout << TimeNow() << " CH authenticated GCS\n";
        std::cout << TimeNow() << " CH -> GCS : M2\n";
        Send(msg, m_gcsAddr);
    }

    void HandleAuthM2(const Bytes& data)
    {
        size_t off = 1;
        Bytes pidOld = ReadBytes(data, off, 4);
        Bytes maskedRNew = ReadBytes(data, off, 32);
        Bytes tau2 = ReadBytes(data, off, 32);
        if (off != data.size())
            throw std::runtime_error("M2 trailing bytes");

        auto& st = m_system->lightGcs;
        if (!CtEqual(pidOld, st.pid))
            throw std::runtime_error("GCS rejected M2: PID mismatch");

        Bytes v = Blake2b36(m_q);
        Bytes n(v.begin(), v.begin() + 32);
        Bytes pidNew(v.begin() + 32, v.begin() + 36);
        Bytes rNew = Xor(maskedRNew, n);

        Bytes tag2Input;
        Append(tag2Input, m_cNew);
        Append(tag2Input, m_q);
        Append(tag2Input, n);
        Append(tag2Input, rNew);
        if (!CtEqual(tau2, Sha256(tag2Input)))
            throw std::runtime_error("GCS rejected M2");

        st.challenge = m_cNew;
        st.response = rNew;
        st.pid = pidNew;
        st.sessionKey = n;

        std::cout << TimeNow() << " GCS authenticated CH\n";
        std::cout << TimeNow()
                  << " [SUCCESS] GCS-CH mutual authentication; rolling CRP updated\n";
        std::cout << TimeNow()
                  << " [Mission setup] authenticated CH information transferred to designated ACC_old over the trusted control channel\n";
    }

    void HandleHandoverM3(const Bytes& data)
    {
        size_t off = 1;
        Bytes pidNew = ReadBytes(data, off, 4);
        uint32_t epochNext = ReadU32(data, off);
        uint16_t u = ReadU16(data, off);
        uint32_t timestampA = ReadU32(data, off);
        Bytes nonceA = ReadBytes(data, off, 32);
        Bytes pkK = ReadBytes(data, off, m_kem->length_public_key);
        Bytes sigA = ReadBytes(data, off, WotsPlus::SIG_LEN);
        if (off != data.size())
            throw std::runtime_error("M3 trailing bytes");

        if (!CtEqual(pidNew, m_system->newAcc.pid))
            throw std::runtime_error("CH rejected M3: PID_new mismatch");
        if (epochNext != m_system->chHo.epoch + 1)
            throw std::runtime_error("CH rejected M3: invalid epoch");

        uint64_t nowMs = static_cast<uint64_t>(Simulator::Now().GetMilliSeconds());
        uint64_t tsMs = timestampA;
        uint64_t diff = (nowMs >= tsMs) ? (nowMs - tsMs) : (tsMs - nowMs);
        if (diff > m_freshnessWindowMs)
            throw std::runtime_error("CH rejected M3: stale timestamp");

        if (u == 0 || u > m_system->credentialCount || m_system->chHo.usedU.count(u))
            throw std::runtime_error("CH rejected M3: invalid/reused ACC WOTS+ index");

        Bytes ctxH = MakeCtxH(m_system->oldAccPid, pidNew, epochNext);
        Bytes dA = MakeDa(ctxH, u, timestampA, nonceA, pkK);
        Bytes recoveredPkA = WotsPlus::RecoverPublicKey(sigA, dA);
        Bytes accLeaf = MakeAccLeaf(pidNew, u, recoveredPkA);
        if (!MerkleTree::Verify(accLeaf,
                                m_system->ledger.accNew.proofs[u - 1],
                                m_system->ledger.accNew.root))
            throw std::runtime_error("CH rejected M3: ACC WOTS+/Merkle verification failed");
        m_system->chHo.usedU.insert(u);

        std::cout << TimeNow() << " CH authenticated ACC_new via WOTS+/Merkle verification\n";

        uint16_t v = NextUnused(m_system->chHo.usedV,
                                m_system->credentialCount);
        m_system->chHo.usedV.insert(v);

        Bytes stableR = FuzzyExtractor::Rep(
            m_system->puf->Evaluate(m_system->ledger.ch.challengeH),
            m_system->chHo.helperH);
        Bytes masterH = HandoverMasterSeed(stableR, m_system->chHo.pidH);
        Bytes chSeed = ChCredentialSeed(masterH, v);

        Bytes nonceI = RandomBytes(32);
        Bytes ct(m_kem->length_ciphertext);
        Bytes kemShared(m_kem->length_shared_secret);
        if (OQS_KEM_encaps(m_kem, ct.data(), kemShared.data(), pkK.data()) != OQS_SUCCESS)
            throw std::runtime_error("ML-KEM encapsulation failed");

        Bytes ctxI = MakeCtxI(ctxH,
                              m_system->chHo.pidH,
                              nonceA,
                              nonceI,
                              pkK,
                              ct);
        Bytes sk = MakeSessionKey(kemShared, ctxI);
        Bytes dI = MakeDi(ctxI, v);
        Bytes sigI = WotsPlus::Sign(chSeed, dI);
        Bytes tau = MakeTau(sk, ctxI);

        m_system->chHo.sessionKey = sk;
        m_system->chHo.epoch = epochNext;

        Bytes msg;
        msg.push_back(HO_M4);
        Append(msg, m_system->chHo.pidH);
        AppendU16(msg, v);
        Append(msg, nonceI);
        Append(msg, ct);
        Append(msg, sigI);
        Append(msg, tau);

        std::cout << TimeNow()
                  << " CH -> ACC_new : M4  [CH authentication + ML-KEM + key confirmation]\n";
        Send(msg, m_newAddr);
    }

    void HandleHandoverM4(const Bytes& data)
    {
        size_t off = 1;
        Bytes pidH = ReadBytes(data, off, 4);
        uint16_t v = ReadU16(data, off);
        Bytes nonceI = ReadBytes(data, off, 32);
        Bytes ct = ReadBytes(data, off, m_kem->length_ciphertext);
        Bytes sigI = ReadBytes(data, off, WotsPlus::SIG_LEN);
        Bytes tau = ReadBytes(data, off, 32);
        if (off != data.size())
            throw std::runtime_error("M4 trailing bytes");

        if (!CtEqual(pidH, m_system->chHo.pidH))
            throw std::runtime_error("ACC_new rejected M4: CH PID mismatch");
        if (v == 0 || v > m_system->credentialCount)
            throw std::runtime_error("ACC_new rejected M4: v out of range");

        Bytes ctxH = MakeCtxH(m_system->oldAccPid,
                              m_system->newAcc.pid,
                              m_pendingEpoch);
        Bytes ctxI = MakeCtxI(ctxH,
                              pidH,
                              m_nonceA,
                              nonceI,
                              m_kemPk,
                              ct);
        Bytes dI = MakeDi(ctxI, v);
        Bytes recoveredPkI = WotsPlus::RecoverPublicKey(sigI, dI);

        Bytes leaf = MakeChLeaf(pidH,
                                v,
                                m_system->ledger.ch.chId,
                                recoveredPkI);
        Bytes zi = ComputeIntermediateRoot(leaf,
                                           m_system->ledger.ch.lower[v - 1]);
        if (!MerkleTree::Verify(zi,
                                m_system->ledger.ch.upper,
                                m_system->ledger.ch.globalRootY))
            throw std::runtime_error("ACC_new rejected M4: CH Merkle verification failed");

        Bytes kemShared(m_kem->length_shared_secret);
        if (OQS_KEM_decaps(m_kem,
                           kemShared.data(),
                           ct.data(),
                           m_kemSk.data()) != OQS_SUCCESS)
            throw std::runtime_error("ML-KEM decapsulation failed");

        Bytes sk = MakeSessionKey(kemShared, ctxI);
        if (!CtEqual(tau, MakeTau(sk, ctxI)))
            throw std::runtime_error("ACC_new rejected M4: HMAC verification failed");

        m_newSessionKey = sk;
        m_system->newAcc.epoch = m_pendingEpoch;

        std::cout << TimeNow() << " ACC_new authenticated CH and verified key confirmation\n";
        std::cout << TimeNow()
                  << " [SUCCESS] Failure-resilient handover complete; fresh CH-ACC_new session established without ACC_old participation\n";
    }

    static Bytes ComputeIntermediateRoot(Bytes leaf, const MerkleProof& proof)
    {
        Bytes cur = std::move(leaf);
        for (const auto& step : proof)
            cur = step.siblingIsLeft ? HashPair(step.sibling, cur)
                                     : HashPair(cur, step.sibling);
        return cur;
    }

    static uint16_t NextUnused(const std::set<uint16_t>& used, size_t max)
    {
        for (uint32_t ii = 1; ii <= max; ++ii)
        {
            uint16_t i = static_cast<uint16_t>(ii);
            if (!used.count(i))
                return i;
        }
        throw std::runtime_error("No unused one-time credential remains");
    }

    static std::string TimeNow()
    {
        std::ostringstream oss;
        oss << "[t=" << std::fixed << std::setprecision(6)
            << Simulator::Now().GetSeconds() << "s]";
        return oss.str();
    }

  private:
    Role m_role{CH};
    std::shared_ptr<SharedSystem> m_system;
    uint16_t m_port{0};
    uint32_t m_freshnessWindowMs{1000};
    Ptr<Socket> m_socket;
    Ipv4Address m_gcsAddr;
    Ipv4Address m_chAddr;
    Ipv4Address m_oldAddr;
    Ipv4Address m_newAddr;
    bool m_available{true};
    OQS_KEM* m_kem{nullptr};

    // Authentication pending state.
    Bytes m_initiator;
    Bytes m_q;
    Bytes m_cNew;

    // Handover pending state at ACC_new.
    uint16_t m_pendingU{0};
    uint32_t m_pendingEpoch{0};
    uint32_t m_timestampA{0};
    Bytes m_nonceA;
    Bytes m_kemPk;
    Bytes m_kemSk;
    Bytes m_newSessionKey;
};

} // namespace parch

int main(int argc, char* argv[])
{
    using namespace parch;

    double authTime = 1.0;
    double failureTime = 4.0;
    double handoverTime = 4.2;
    double stopTime = 7.0;
    double pufBitErrorRate = 0.001;
    uint32_t credentialCount = 1024;
    uint32_t enrolledChCount = 10;
    uint32_t freshnessWindowMs = 1000;
    uint32_t rngSeed = 7;

    CommandLine cmd(__FILE__);
    cmd.AddValue("authTime", "Time at which CH sends authentication M0", authTime);
    cmd.AddValue("failureTime", "Time at which ACC_old becomes unavailable", failureTime);
    cmd.AddValue("handoverTime", "Time at which ACC_new starts handover", handoverTime);
    cmd.AddValue("stopTime", "Simulation stop time", stopTime);
    cmd.AddValue("pufBitErrorRate", "Injected raw-PUF bit error probability", pufBitErrorRate);
    cmd.AddValue("credentialCount", "Number m of enrolled WOTS+ credentials", credentialCount);
    cmd.AddValue("enrolledChCount", "Number n of CH roots in upper Merkle tree", enrolledChCount);
    cmd.AddValue("freshnessWindowMs", "Allowed M3 timestamp window in milliseconds", freshnessWindowMs);
    cmd.AddValue("rngSeed", "ns-3 RNG seed", rngSeed);
    cmd.Parse(argc, argv);

    if (credentialCount == 0 || credentialCount > 65534)
        throw std::runtime_error("credentialCount must be in [1,65534]");
    if (enrolledChCount == 0)
        throw std::runtime_error("enrolledChCount must be positive");

    RngSeedManager::SetSeed(rngSeed);

    auto system = std::make_shared<SharedSystem>(pufBitErrorRate);
    system->credentialCount = credentialCount;
    system->enrolledChCount = enrolledChCount;
    EnrollSystem(system);

    NodeContainer nodes;
    nodes.Create(4);
    Ptr<Node> gcsNode = nodes.Get(0);
    Ptr<Node> chNode = nodes.Get(1);
    Ptr<Node> oldNode = nodes.Get(2);
    Ptr<Node> newNode = nodes.Get(3);

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211g);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue("ErpOfdmRate6Mbps"),
                                 "ControlMode", StringValue("ErpOfdmRate6Mbps"));

    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::FriisPropagationLossModel");

    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    phy.Set("TxPowerStart", DoubleValue(20.0));
    phy.Set("TxPowerEnd", DoubleValue(20.0));

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    MobilityHelper mobility;
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();
    pos->Add(Vector(-40.0, 0.0, 20.0)); // GCS
    pos->Add(Vector(0.0, 0.0, 50.0));   // CH
    pos->Add(Vector(60.0, 0.0, 80.0));  // ACC_old
    pos->Add(Vector(80.0, 20.0, 80.0)); // ACC_new
    mobility.SetPositionAllocator(pos);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    Ipv4Address gcsAddr = ifaces.GetAddress(0);
    Ipv4Address chAddr = ifaces.GetAddress(1);
    Ipv4Address oldAddr = ifaces.GetAddress(2);
    Ipv4Address newAddr = ifaces.GetAddress(3);

    constexpr uint16_t port = 9000;

    Ptr<ParchApp> gcsApp = CreateObject<ParchApp>();
    Ptr<ParchApp> chApp = CreateObject<ParchApp>();
    Ptr<ParchApp> oldApp = CreateObject<ParchApp>();
    Ptr<ParchApp> newApp = CreateObject<ParchApp>();

    gcsApp->Configure(ParchApp::GCS, system, port, freshnessWindowMs);
    chApp->Configure(ParchApp::CH, system, port, freshnessWindowMs);
    oldApp->Configure(ParchApp::ACC_OLD, system, port, freshnessWindowMs);
    newApp->Configure(ParchApp::ACC_NEW, system, port, freshnessWindowMs);

    gcsApp->SetPeers(gcsAddr, chAddr, oldAddr, newAddr);
    chApp->SetPeers(gcsAddr, chAddr, oldAddr, newAddr);
    oldApp->SetPeers(gcsAddr, chAddr, oldAddr, newAddr);
    newApp->SetPeers(gcsAddr, chAddr, oldAddr, newAddr);

    gcsNode->AddApplication(gcsApp);
    chNode->AddApplication(chApp);
    oldNode->AddApplication(oldApp);
    newNode->AddApplication(newApp);

    for (auto app : {gcsApp, chApp, oldApp, newApp})
    {
        app->SetStartTime(Seconds(0.1));
        app->SetStopTime(Seconds(stopTime));
    }

    Simulator::Schedule(Seconds(authTime),
                        &ParchApp::StartInitialAuthentication,
                        chApp);
    Simulator::Schedule(Seconds(failureTime),
                        &ParchApp::FailOldAcc,
                        oldApp);
    Simulator::Schedule(Seconds(handoverTime),
                        &ParchApp::StartHandover,
                        newApp);

    std::cout << "=== PARCH ns-3 functional validation ===\n"
              << "GCS     : " << gcsAddr << "\n"
              << "CH      : " << chAddr << "\n"
              << "ACC_old : " << oldAddr << "\n"
              << "ACC_new : " << newAddr << "\n"
              << "m       : " << credentialCount << " WOTS+ credentials\n"
              << "n       : " << enrolledChCount << " CH roots\n"
              << "PUF BER : " << pufBitErrorRate << "\n\n";

    Simulator::Stop(Seconds(stopTime));
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
