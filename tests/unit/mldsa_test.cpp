// Copyright (c) 2024 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uhs/client/client.hpp"
#include "uhs/transaction/messages.hpp"
#include "uhs/transaction/validation.hpp"
#include "uhs/transaction/wallet.hpp"
#include "util/common/mldsa.hpp"
#include "util/serialization/format.hpp"

#include <gtest/gtest.h>

namespace {
    auto to_hex(const cbdc::pq_pubkey_t& pk) -> std::string {
        static constexpr auto digits = "0123456789abcdef";
        std::string out;
        out.reserve(pk.size() * 2);
        for(const auto b : pk) {
            out.push_back(digits[b >> 4]);
            out.push_back(digits[b & 0xf]);
        }
        return out;
    }
}

TEST(mldsa, sign_verify) {
    cbdc::pq_pubkey_t pk{};
    cbdc::pq_privkey_t sk{};
    ASSERT_TRUE(cbdc::mldsa_keypair(pk, sk));

    std::array<unsigned char, 32> msg{};
    msg.fill(0x42);

    cbdc::pq_signature_t sig{};
    ASSERT_TRUE(cbdc::mldsa_sign(msg.data(), msg.size(), sk, sig));
    EXPECT_TRUE(cbdc::mldsa_verify(msg.data(), msg.size(), sig, pk));

    // Tampered message.
    auto bad_msg = msg;
    bad_msg[0] ^= 0x01;
    EXPECT_FALSE(cbdc::mldsa_verify(bad_msg.data(), bad_msg.size(), sig, pk));

    // Tampered signature.
    auto bad_sig = sig;
    bad_sig[0] ^= 0x01;
    EXPECT_FALSE(cbdc::mldsa_verify(msg.data(), msg.size(), bad_sig, pk));

    // Wrong public key.
    cbdc::pq_pubkey_t other_pk{};
    cbdc::pq_privkey_t other_sk{};
    ASSERT_TRUE(cbdc::mldsa_keypair(other_pk, other_sk));
    EXPECT_FALSE(cbdc::mldsa_verify(msg.data(), msg.size(), sig, other_pk));
}

TEST(mldsa, pubkey_from_privkey) {
    // FIPS 204 secret keys omit t1, so pk_from_sk must recompute it. Verify it
    // exactly reproduces the keypair's public key.
    for(size_t i = 0; i < 5; i++) {
        cbdc::pq_pubkey_t pk{};
        cbdc::pq_privkey_t sk{};
        ASSERT_TRUE(cbdc::mldsa_keypair(pk, sk));
        EXPECT_EQ(cbdc::mldsa_pubkey_from_privkey(sk), pk);
    }
}

TEST(mldsa, compact_tx_attestation_roundtrip) {
    cbdc::transaction::wallet w;
    auto mint = w.mint_new_coins(1, 100);
    w.confirm_transaction(mint);
    auto full = w.send_to(5, w.generate_key(), true).value();

    cbdc::pq_pubkey_t pk{};
    cbdc::pq_privkey_t sk{};
    ASSERT_TRUE(cbdc::mldsa_keypair(pk, sk));

    auto ctx = cbdc::transaction::compact_tx(full);
    ctx.m_attestations.insert(ctx.sign(sk, 0));

    auto buf = cbdc::make_buffer(ctx);
    auto restored = cbdc::from_buffer<cbdc::transaction::compact_tx>(buf);
    ASSERT_TRUE(restored.has_value());

    const auto& att = *ctx.m_attestations.begin();
    EXPECT_EQ(att.first, 0U);
    EXPECT_TRUE(restored->verify(att, pk));

    const auto pubkeys = std::unordered_map<size_t, cbdc::pq_pubkey_t>{{0, pk}};
    EXPECT_TRUE(cbdc::transaction::validation::check_attestations(
        *restored,
        pubkeys,
        1));
}

TEST(mldsa, precomputed_sign) {
    cbdc::pq_pubkey_t pk{};
    cbdc::pq_privkey_t sk{};
    ASSERT_TRUE(cbdc::mldsa_keypair(pk, sk));

    const auto pre = cbdc::mldsa_precompute(sk);
    ASSERT_FALSE(pre.empty());

    std::array<unsigned char, 32> msg{};
    msg.fill(0x11);
    cbdc::pq_signature_t sig{};
    ASSERT_TRUE(cbdc::mldsa_sign_precomputed(msg.data(), msg.size(), pre, sig));
    EXPECT_TRUE(cbdc::mldsa_verify(msg.data(), msg.size(), sig, pk));

    // The sentinel path: precomputed context produces verifiable attestations.
    cbdc::transaction::wallet w;
    auto mint = w.mint_new_coins(1, 100);
    w.confirm_transaction(mint);
    auto full = w.send_to(5, w.generate_key(), true).value();
    auto ctx = cbdc::transaction::compact_tx(full);
    const auto att = ctx.sign(pre, 0);
    EXPECT_TRUE(ctx.verify(att, pk));
}

TEST(mldsa, address_hex_decode) {
    cbdc::pq_pubkey_t pk{};
    cbdc::pq_privkey_t sk{};
    ASSERT_TRUE(cbdc::mldsa_keypair(pk, sk));

    const auto hex = to_hex(pk);
    auto decoded = cbdc::address::decode(hex);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), pk);

    // Wrong length and non-hex input are rejected.
    EXPECT_FALSE(cbdc::address::decode(hex.substr(1)).has_value());
    auto bad = hex;
    bad[0] = 'z';
    EXPECT_FALSE(cbdc::address::decode(bad).has_value());
}
