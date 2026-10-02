// Copyright (c) 2024 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OPENCBDC_TX_SRC_COMMON_MLDSA_H_
#define OPENCBDC_TX_SRC_COMMON_MLDSA_H_

#include <array>
#include <cstddef>
#include <vector>

/**
 * \file mldsa.hpp
 * Thin abstraction over the vendored FIPS 204 ML-DSA implementation used by
 * the UHS (2PC and atomizer) architectures.
 *
 * PArSEC's EVM continues to use secp256k1 keys from keys.hpp for Ethereum
 * compatibility; the types here are deliberately separate so the two schemes
 * can coexist.
 *
 * Error model: all calls use the empty FIPS 204 context. In that case the
 * reference implementation cannot fail key generation or signing (the RNG
 * aborts on failure and the signing rejection loop only ever returns success),
 * so the bool results of \ref mldsa_keypair and \ref mldsa_sign are always
 * true. Only \ref mldsa_verify reports a meaningful error.
 */

namespace cbdc {
#ifndef MLDSA_MODE
#define MLDSA_MODE 2
#endif

#if MLDSA_MODE == 2
    /// ML-DSA-44 public key size, in bytes.
    static constexpr size_t mldsa_pubkey_len = 1312;
    /// ML-DSA-44 private key size, in bytes.
    static constexpr size_t mldsa_privkey_len = 2560;
    /// ML-DSA-44 signature size, in bytes.
    static constexpr size_t mldsa_sig_len = 2420;
#elif MLDSA_MODE == 3
    static constexpr size_t mldsa_pubkey_len = 1952;
    static constexpr size_t mldsa_privkey_len = 4032;
    static constexpr size_t mldsa_sig_len = 3309;
#elif MLDSA_MODE == 5
    static constexpr size_t mldsa_pubkey_len = 2592;
    static constexpr size_t mldsa_privkey_len = 4896;
    static constexpr size_t mldsa_sig_len = 4627;
#else
#error "MLDSA_MODE must be 2 (ML-DSA-44), 3 (ML-DSA-65), or 5 (ML-DSA-87)"
#endif

    /// A UHS ML-DSA public key.
    using pq_pubkey_t = std::array<unsigned char, mldsa_pubkey_len>;
    /// A UHS ML-DSA private key.
    using pq_privkey_t = std::array<unsigned char, mldsa_privkey_len>;
    /// A UHS ML-DSA signature.
    using pq_signature_t = std::array<unsigned char, mldsa_sig_len>;

    /// Generates a new ML-DSA keypair from the system RNG.
    /// \param pk output public key.
    /// \param sk output private key.
    /// \return true on success.
    auto mldsa_keypair(pq_pubkey_t& pk, pq_privkey_t& sk) -> bool;

    /// Derives the public key corresponding to a private key (FIPS 204,
    /// Algorithm 6). This recomputes t1, which is not stored in the packed
    /// secret key, so it is relatively expensive compared to signing.
    /// \param sk private key.
    /// \return the corresponding public key.
    auto mldsa_pubkey_from_privkey(const pq_privkey_t& sk) -> pq_pubkey_t;

    /// Signs a message digest (FIPS 204 pure ML-DSA, empty context).
    /// \param msg message to sign.
    /// \param len length of the message in bytes.
    /// \param sk private key with which to sign.
    /// \param sig output signature buffer.
    /// \return true on success.
    auto mldsa_sign(const unsigned char* msg,
                    size_t len,
                    const pq_privkey_t& sk,
                    pq_signature_t& sig) -> bool;

    /// An opaque, precomputed signing context for a single private key.
    using pq_sign_ctx_t = std::vector<std::byte>;

    /// Precomputes the key-dependent part of ML-DSA signing (the matrix A and
    /// the NTTs of s1/s2/t0). Worth it when many signatures are produced under
    /// one key, e.g. by a sentinel. Returns an empty context if the key is
    /// invalid (it cannot be, for well-formed keys).
    /// \param sk private key with which to sign.
    /// \return the precomputed signing context.
    auto mldsa_precompute(const pq_privkey_t& sk) -> pq_sign_ctx_t;

    /// Signs using a context produced by \ref mldsa_precompute.
    /// \param msg message to sign.
    /// \param len length of the message in bytes.
    /// \param ctx precomputed signing context.
    /// \param sig output signature buffer.
    /// \return true on success.
    auto mldsa_sign_precomputed(const unsigned char* msg,
                                size_t len,
                                const pq_sign_ctx_t& ctx,
                                pq_signature_t& sig) -> bool;

    /// Verifies an ML-DSA signature (FIPS 204 pure ML-DSA, empty context).
    /// \param msg signed message.
    /// \param len length of the message in bytes.
    /// \param sig signature to verify.
    /// \param pk public key of the purported signer.
    /// \return true if the signature is valid.
    auto mldsa_verify(const unsigned char* msg,
                      size_t len,
                      const pq_signature_t& sig,
                      const pq_pubkey_t& pk) -> bool;
}

#endif // OPENCBDC_TX_SRC_COMMON_MLDSA_H_
