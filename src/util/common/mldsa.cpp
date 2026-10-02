// Copyright (c) 2024 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mldsa.hpp"

extern "C" {
#include <api.h>

/// Implemented in 3rdparty/mldsa/mldsa_extra.c using the reference
/// implementation internals.
void mldsa_pk_from_sk(uint8_t* pk, const uint8_t* sk);
size_t mldsa_ctx_size(void);
void mldsa_ctx_init(uint8_t* ctx, const uint8_t* sk);
int mldsa_ctx_sign(uint8_t* sig,
                   size_t* siglen,
                   const uint8_t* m,
                   size_t mlen,
                   const uint8_t* ctx);
}

namespace cbdc {
#if MLDSA_MODE == 2
#define MLD_KEYPAIR pqcrystals_dilithium2_ref_keypair
#define MLD_SIGNATURE pqcrystals_dilithium2_ref_signature
#define MLD_VERIFY pqcrystals_dilithium2_ref_verify
#define MLD_PK_BYTES pqcrystals_dilithium2_PUBLICKEYBYTES
#define MLD_SK_BYTES pqcrystals_dilithium2_SECRETKEYBYTES
#define MLD_SIG_BYTES pqcrystals_dilithium2_BYTES
#elif MLDSA_MODE == 3
#define MLD_KEYPAIR pqcrystals_dilithium3_ref_keypair
#define MLD_SIGNATURE pqcrystals_dilithium3_ref_signature
#define MLD_VERIFY pqcrystals_dilithium3_ref_verify
#define MLD_PK_BYTES pqcrystals_dilithium3_PUBLICKEYBYTES
#define MLD_SK_BYTES pqcrystals_dilithium3_SECRETKEYBYTES
#define MLD_SIG_BYTES pqcrystals_dilithium3_BYTES
#elif MLDSA_MODE == 5
#define MLD_KEYPAIR pqcrystals_dilithium5_ref_keypair
#define MLD_SIGNATURE pqcrystals_dilithium5_ref_signature
#define MLD_VERIFY pqcrystals_dilithium5_ref_verify
#define MLD_PK_BYTES pqcrystals_dilithium5_PUBLICKEYBYTES
#define MLD_SK_BYTES pqcrystals_dilithium5_SECRETKEYBYTES
#define MLD_SIG_BYTES pqcrystals_dilithium5_BYTES
#endif

    static_assert(mldsa_pubkey_len == MLD_PK_BYTES);
    static_assert(mldsa_privkey_len == MLD_SK_BYTES);
    static_assert(mldsa_sig_len == MLD_SIG_BYTES);

    auto mldsa_keypair(pq_pubkey_t& pk, pq_privkey_t& sk) -> bool {
        return MLD_KEYPAIR(pk.data(), sk.data()) == 0;
    }

    auto mldsa_pubkey_from_privkey(const pq_privkey_t& sk) -> pq_pubkey_t {
        pq_pubkey_t pk{};
        mldsa_pk_from_sk(pk.data(), sk.data());
        return pk;
    }

    auto mldsa_sign(const unsigned char* msg,
                    size_t len,
                    const pq_privkey_t& sk,
                    pq_signature_t& sig) -> bool {
        auto siglen = size_t{0};
        return MLD_SIGNATURE(sig.data(),
                             &siglen,
                             msg,
                             len,
                             nullptr,
                             0,
                             sk.data())
            == 0;
    }

    auto mldsa_precompute(const pq_privkey_t& sk) -> pq_sign_ctx_t {
        auto ctx = pq_sign_ctx_t(mldsa_ctx_size());
        mldsa_ctx_init(reinterpret_cast<uint8_t*>(ctx.data()), sk.data());
        return ctx;
    }

    auto mldsa_sign_precomputed(const unsigned char* msg,
                                size_t len,
                                const pq_sign_ctx_t& ctx,
                                pq_signature_t& sig) -> bool {
        auto siglen = size_t{0};
        return mldsa_ctx_sign(sig.data(),
                              &siglen,
                              msg,
                              len,
                              reinterpret_cast<const uint8_t*>(ctx.data()))
            == 0;
    }

    auto mldsa_verify(const unsigned char* msg,
                      size_t len,
                      const pq_signature_t& sig,
                      const pq_pubkey_t& pk) -> bool {
        return MLD_VERIFY(sig.data(),
                          sig.size(),
                          msg,
                          len,
                          nullptr,
                          0,
                          pk.data())
            == 0;
    }
}
