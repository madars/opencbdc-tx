// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OPENCBDC_TX_SRC_COMMON_HASHMAP_H_
#define OPENCBDC_TX_SRC_COMMON_HASHMAP_H_

#include "buffer.hpp"
#include "crypto/siphash.h"
#include "hash.hpp"

#include <array>
#include <cstring>

namespace cbdc::hashing {
    /// \brief SipHash function to generate STL data structure hash keys for
    ///        system IDs.
    ///
    /// [TODO: Uses randomly generated initialization keys to insure that
    /// colliding values will differ from run to run.] For transaction data
    /// that comes from users, it is important to key data in sets and hashmaps
    /// non-deterministically. Otherwise, malicious actors might pre-calculate
    /// colliding values and spam the system with them to cripple performance.
    /// \tparam T hash-like type to hash.
    template<class T>
    struct const_sip_hash {
        static_assert(std::is_trivial_v<T>);
        auto operator()(T const& tx) const noexcept -> size_t {
            // TODO: pick the initialization key at random.
            static constexpr std::array<uint64_t, 2> siphash_key{0x1337,
                                                                 0x1337};
            CSipHasher hasher(siphash_key[0], siphash_key[1]);
            std::array<unsigned char, sizeof(tx)> tx_arr{};
            std::memcpy(tx_arr.data(), &tx, sizeof(tx));
            hasher.Write(tx_arr.data(), sizeof(tx));
            return hasher.Finalize();
        }
    };

    template<>
    struct const_sip_hash<buffer> {
        auto operator()(const buffer& buf) const noexcept -> size_t {
            // TODO: pick the initialization key at random.
            static constexpr std::array<uint64_t, 2> siphash_key{0x1337,
                                                                 0x1337};
            CSipHasher hasher(siphash_key[0], siphash_key[1]);
            std::vector<unsigned char> arr(buf.size());
            std::memcpy(arr.data(), buf.data(), buf.size());
            hasher.Write(arr.data(), arr.size());
            return hasher.Finalize();
        }
    };

    /// \brief Uses the raw leading bytes of a provided hash-like value as an
    ///        STL data structure hash key.
    ///
    /// Works with any container exposing `data()`, including large ML-DSA
    /// public keys. Hash collisions are resolved by the container's equality
    /// comparison, so only the leading bytes are used.
    ///
    /// \warning Only use with values whose leading bytes have sufficiently
    ///          high entropy to guarantee a low likelihood of collisions.
    struct null {
        template<typename T>
        auto operator()(const T& value) const noexcept -> size_t {
            static_assert(sizeof(T) >= sizeof(size_t));
            size_t ret{};
            std::memcpy(&ret, value.data(), sizeof(ret));
            return ret;
        }
    };
}

#endif // OPENCBDC_TX_SRC_COMMON_HASHMAP_H_
