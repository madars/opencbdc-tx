// Copyright (c) 2024 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Microbenchmark for the per-transaction work a 2PC sentinel performs:
//   1. statically validate the full transaction (input witness signatures,
//      witness-program commitments, tx ID hashing)
//   2. build the compact transaction
//   3. sign the compact transaction (sentinel attestation)
//
// Runs the pipeline for the current ML-DSA UHS implementation and, for
// comparison, for the legacy secp256k1 Schnorr witness format.

#include "crypto/sha256.h"
#include "uhs/transaction/messages.hpp"
#include "uhs/transaction/validation.hpp"
#include "uhs/transaction/wallet.hpp"

#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <vector>

namespace {
    constexpr size_t legacy_pubkey_len = 32;
    constexpr size_t legacy_sig_len = 64;
    constexpr size_t legacy_prog_len = 1 + legacy_pubkey_len;
    constexpr size_t legacy_witness_len = legacy_prog_len + legacy_sig_len;

    double now_us() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::high_resolution_clock::now()
                       .time_since_epoch())
                   .count()
            / 1000.0;
    }

    struct secp_ctx {
        secp256k1_context* ctx{secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)};
        ~secp_ctx() {
            secp256k1_context_destroy(ctx);
        }
    };

    auto schnorr_keypair(secp256k1_context* ctx, unsigned char* seckey)
        -> cbdc::hash_t {
        secp256k1_keypair kp{};
        while(secp256k1_keypair_create(ctx, &kp, seckey) != 1) {
            seckey[0]++;
        }
        secp256k1_xonly_pubkey xpub{};
        [[maybe_unused]] const auto pub_ret
            = secp256k1_keypair_xonly_pub(ctx, &xpub, nullptr, &kp);
        assert(pub_ret == 1);
        cbdc::hash_t pk{};
        [[maybe_unused]] const auto ser_ret
            = secp256k1_xonly_pubkey_serialize(ctx, pk.data(), &xpub);
        assert(ser_ret == 1);
        return pk;
    }

    void schnorr_sign(secp256k1_context* ctx,
                      const unsigned char* seckey,
                      const cbdc::hash_t& msg,
                      unsigned char* sig) {
        secp256k1_keypair kp{};
        [[maybe_unused]] const auto kp_ret
            = secp256k1_keypair_create(ctx, &kp, seckey);
        assert(kp_ret == 1);
        [[maybe_unused]] const auto sign_ret
            = secp256k1_schnorrsig_sign32(ctx,
                                          sig,
                                          msg.data(),
                                          &kp,
                                          nullptr);
        assert(sign_ret == 1);
    }

    auto as_uchar(const std::byte* p) -> const unsigned char* {
        return reinterpret_cast<const unsigned char*>(p);
    }

    // Reimplementation of the legacy 2PC witness validation (secp256k1
    // Schnorr, witness = [type][32B xonly pubkey][64B sig]).
    auto legacy_validate(const cbdc::transaction::full_tx& tx,
                         secp256k1_context* ctx) -> bool {
        const auto sighash = cbdc::transaction::tx_id(tx);
        for(size_t i = 0; i < tx.m_inputs.size(); i++) {
            const auto& wit = tx.m_witness[i];
            if(wit.size() != legacy_witness_len) {
                return false;
            }
            if(cbdc::hash_data(wit.data(), legacy_prog_len)
               != tx.m_inputs[i]
                      .m_prevout_data.m_witness_program_commitment) {
                return false;
            }
            secp256k1_xonly_pubkey pub{};
            if(secp256k1_xonly_pubkey_parse(ctx, &pub, as_uchar(&wit[1]))
               != 1) {
                return false;
            }
            if(secp256k1_schnorrsig_verify(ctx,
                                           as_uchar(&wit[legacy_prog_len]),
                                           sighash.data(),
                                           sighash.size(),
                                           &pub)
               != 1) {
                return false;
            }
        }
        return true;
    }

    auto legacy_tx(size_t inputs, secp256k1_context* ctx)
        -> cbdc::transaction::full_tx {
        cbdc::transaction::full_tx tx;
        unsigned char sk[32] = {1};
        const auto pk = schnorr_keypair(ctx, sk);

        std::vector<std::byte> prog(legacy_prog_len);
        prog[0] = std::byte(0);
        std::memcpy(&prog[1], pk.data(), pk.size());
        const auto commit = cbdc::hash_data(prog.data(), prog.size());

        for(size_t i = 0; i < inputs; i++) {
            cbdc::transaction::input in;
            in.m_prevout.m_tx_id.fill(static_cast<unsigned char>(i + 1));
            in.m_prevout.m_index = i;
            in.m_prevout_data.m_witness_program_commitment = commit;
            in.m_prevout_data.m_value = 100;
            tx.m_inputs.push_back(in);
        }

        cbdc::transaction::output out;
        out.m_value = 100 * inputs;
        out.m_witness_program_commitment.fill(0xAB);
        tx.m_outputs.push_back(out);

        const auto sighash = cbdc::transaction::tx_id(tx);
        for(size_t i = 0; i < inputs; i++) {
            std::vector<std::byte> wit(legacy_witness_len);
            wit[0] = std::byte(0);
            std::memcpy(&wit[1], pk.data(), pk.size());
            schnorr_sign(ctx,
                         sk,
                         sighash,
                         reinterpret_cast<unsigned char*>(
                             &wit[legacy_prog_len]));
            tx.m_witness.push_back(std::move(wit));
        }
        return tx;
    }

    auto pq_tx(size_t inputs) -> cbdc::transaction::full_tx {
        cbdc::transaction::wallet wallet;
        auto mint = wallet.mint_new_coins(inputs, 100);
        wallet.confirm_transaction(mint);
        auto tx = wallet.send_to(inputs, inputs, wallet.generate_key(), true);
        return std::move(tx.value());
    }

    struct result {
        double validate_us{};
        double compact_us{};
        double attest_us{};
    };

    void report(const char* scheme, size_t inputs, const result& r) {
        const auto total = r.validate_us + r.compact_us + r.attest_us;
        std::printf(
            "  %-8s inputs=%zu  validate=%8.1f us  compact=%6.1f us  "
            "attest=%8.1f us  total=%8.1f us  (~%.0f tx/s/sentinel)\n",
            scheme,
            inputs,
            r.validate_us,
            r.compact_us,
            r.attest_us,
            total,
            total > 0 ? 1e6 / total : 0.0);
    }
}

int main(int argc, char** argv) {
    const auto iters = argc > 1 ? std::atol(argv[1]) : 200;
    const auto schnorr_iters = iters * 20;
    secp_ctx secp;

    for(const size_t inputs : {size_t(1), size_t(2), size_t(4)}) {
        std::printf("inputs=%zu\n", inputs);

        // ---- PQ (ML-DSA) ----
        {
            const auto tx = pq_tx(inputs);

            const double t0 = now_us();
            for(long i = 0; i < iters; i++) {
                if(cbdc::transaction::validation::check_tx(tx).has_value()) {
                    std::fprintf(stderr, "pq validation failed\n");
                    return 1;
                }
            }
            const double t1 = now_us();

            const double t2 = now_us();
            cbdc::transaction::compact_tx ctx{};
            for(long i = 0; i < iters; i++) {
                ctx = cbdc::transaction::compact_tx(tx);
            }
            const double t3 = now_us();

            cbdc::pq_pubkey_t sentinel_pub{};
            cbdc::pq_privkey_t sentinel_priv{};
            cbdc::mldsa_keypair(sentinel_pub, sentinel_priv);

            const double t4 = now_us();
            for(long i = 0; i < iters; i++) {
                auto att = ctx.sign(sentinel_priv, 0);
                (void)att;
            }
            const double t5 = now_us();

            const auto pre = cbdc::mldsa_precompute(sentinel_priv);
            const double t6 = now_us();
            for(long i = 0; i < iters; i++) {
                auto att = ctx.sign(pre, 0);
                (void)att;
            }
            const double t7 = now_us();

            report("ml-dsa",
                   inputs,
                   {(t1 - t0) / iters,
                    (t3 - t2) / iters,
                    (t5 - t4) / iters});
            std::printf("  %-8s inputs=%zu  attest(precomputed)=%8.1f us\n",
                        "ml-dsa",
                        inputs,
                        (t7 - t6) / iters);
        }

        // ---- Legacy Schnorr ----
        {
            const auto tx = legacy_tx(inputs, secp.ctx);

            const double t0 = now_us();
            for(long i = 0; i < schnorr_iters; i++) {
                if(!legacy_validate(tx, secp.ctx)) {
                    std::fprintf(stderr, "schnorr validation failed\n");
                    return 1;
                }
            }
            const double t1 = now_us();

            const double t2 = now_us();
            cbdc::transaction::compact_tx ctx{};
            for(long i = 0; i < schnorr_iters; i++) {
                ctx = cbdc::transaction::compact_tx(tx);
            }
            const double t3 = now_us();

            unsigned char sk[32] = {1};
            schnorr_keypair(secp.ctx, sk);
            unsigned char sig[64]{};
            const auto msg = ctx.hash();

            const double t4 = now_us();
            for(long i = 0; i < schnorr_iters; i++) {
                schnorr_sign(secp.ctx, sk, msg, sig);
            }
            const double t5 = now_us();

            report("schnorr",
                   inputs,
                   {(t1 - t0) / schnorr_iters,
                    (t3 - t2) / schnorr_iters,
                    (t5 - t4) / schnorr_iters});
        }
        std::printf("\n");
    }
    return 0;
}
