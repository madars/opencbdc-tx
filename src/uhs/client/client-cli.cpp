// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "atomizer_client.hpp"
#include "client.hpp"
#include "crypto/sha256.h"
#include "twophase_client.hpp"
#include "uhs/transaction/messages.hpp"
#include "util/common/config.hpp"
#include "util/serialization/util.hpp"

#include <future>
#include <iostream>

auto mint_command(cbdc::client& client, const std::vector<std::string>& args)
    -> bool {
    static constexpr auto min_mint_arg_count = 7;
    if(args.size() < min_mint_arg_count) {
        std::cerr << "Mint requires args <n outputs> <output value>"
                  << std::endl;
        return false;
    }

    const auto n_outputs = std::stoull(args[5]);
    const auto output_val = std::stoul(args[6]);

    const auto mint_tx
        = client.mint(n_outputs, static_cast<uint32_t>(output_val));
    std::cout << cbdc::to_string(cbdc::transaction::tx_id(mint_tx))
              << std::endl;
    return true;
}

void print_tx_result(
    const std::optional<cbdc::transaction::full_tx>& tx,
    const std::optional<cbdc::sentinel::execute_response>& resp,
    const cbdc::pq_pubkey_t& pubkey) {
    std::cout << "tx_id:" << std::endl
              << cbdc::to_string(cbdc::transaction::tx_id(tx.value()))
              << std::endl;
    const auto inputs = cbdc::client::export_send_inputs(tx.value(), pubkey);
    for(const auto& inp : inputs) {
        auto buf = cbdc::make_buffer(inp);
        std::cout << "Data for recipient importinput:" << std::endl
                  << buf.to_hex() << std::endl;
    }

    if(resp.has_value()) {
        std::cout << "Sentinel responded: "
                  << cbdc::sentinel::to_string(resp.value().m_tx_status)
                  << std::endl;
        if(resp.value().m_tx_error.has_value()) {
            std::cout << "Validation error: "
                      << cbdc::transaction::validation::to_string(
                             resp.value().m_tx_error.value())
                      << std::endl;
        }
    }
}

auto send_command(cbdc::client& client, const std::vector<std::string>& args)
    -> bool {
    static constexpr auto min_send_arg_count = 7;
    if(args.size() < min_send_arg_count) {
        std::cerr << "Send requires args <value> <pubkey>" << std::endl;
        return false;
    }

    const auto value = std::stoul(args[5]);
    static constexpr auto address_arg_idx = 6;
    auto pubkey = cbdc::address::decode(args[address_arg_idx]);
    if(!pubkey.has_value()) {
        std::cout << "Could not decode address" << std::endl;
        return false;
    }

    const auto [tx, resp]
        = client.send(static_cast<uint32_t>(value), pubkey.value());
    if(!tx.has_value()) {
        std::cout << "Could not generate valid send tx." << std::endl;
        return false;
    }

    print_tx_result(tx, resp, pubkey.value());
    return true;
}

auto fan_command(cbdc::client& client, const std::vector<std::string>& args)
    -> bool {
    static constexpr auto min_fan_arg_count = 8;
    if(args.size() < min_fan_arg_count) {
        std::cerr << "Fan requires args <count> <value> <pubkey>" << std::endl;
        return false;
    }

    const auto value = std::stoul(args[6]);
    const auto count = std::stoul(args[5]);

    static constexpr auto address_arg_idx = 7;
    auto pubkey = cbdc::address::decode(args[address_arg_idx]);
    if(!pubkey.has_value()) {
        std::cout << "Could not decode address" << std::endl;
        return false;
    }

    const auto [tx, resp] = client.fan(static_cast<uint32_t>(count),
                                       static_cast<uint32_t>(value),
                                       pubkey.value());
    if(!tx.has_value()) {
        std::cout << "Could not generate valid send tx." << std::endl;
        return false;
    }

    print_tx_result(tx, resp, pubkey.value());
    return true;
}

void newaddress_command(cbdc::client& client) {
    const auto addr = client.new_address();
    // Research prototype: addresses are the raw ML-DSA public key in hex.
    static constexpr auto hex_digits = "0123456789abcdef";
    for(const auto b : addr) {
        std::cout << hex_digits[b >> 4] << hex_digits[b & 0xf];
    }
    std::cout << std::endl;
}

auto importinput_command(cbdc::client& client,
                         const std::vector<std::string>& args) -> bool {
    static constexpr auto input_arg_idx = 5;
    auto buffer = cbdc::buffer::from_hex(args[input_arg_idx]);
    if(!buffer.has_value()) {
        std::cout << "Invalid input encoding." << std::endl;
        return false;
    }

    auto in = cbdc::from_buffer<cbdc::transaction::input>(buffer.value());
    if(!in.has_value()) {
        std::cout << "Invalid input" << std::endl;
        return false;
    }
    client.import_send_input(in.value());
    return true;
}

auto confirmtx_command(cbdc::client& client,
                       const std::vector<std::string>& args) -> bool {
    const auto tx_id = cbdc::hash_from_hex(args[5]);
    auto success = client.confirm_transaction(tx_id);
    if(!success) {
        std::cout << "Unknown TXID" << std::endl;
        return false;
    }
    std::cout << "Confirmed. Balance: "
              << cbdc::client::print_amount(client.balance())
              << " UTXOs: " << client.utxo_count() << std::endl;
    return true;
}

// LCOV_EXCL_START
auto main(int argc, char** argv) -> int {
    auto args = cbdc::config::get_args(argc, argv);
    static constexpr auto min_arg_count = 5;
    if(args.size() < min_arg_count) {
        std::cerr << "Usage: " << args[0]
                  << " <config file> <client file> <wallet file> <command>"
                  << " <args...>" << std::endl;
        return 0;
    }

    auto cfg_or_err = cbdc::config::load_options(args[1]);
    if(std::holds_alternative<std::string>(cfg_or_err)) {
        std::cerr << "Error loading config file: "
                  << std::get<std::string>(cfg_or_err) << std::endl;
        return -1;
    }

    auto opts = std::get<cbdc::config::options>(cfg_or_err);

    SHA256AutoDetect();

    const auto wallet_file = args[3];
    const auto client_file = args[2];

    auto logger = std::make_shared<cbdc::logging::log>(
        cbdc::config::defaults::log_level);

    auto client = std::unique_ptr<cbdc::client>();
    if(opts.m_twophase_mode) {
        client = std::make_unique<cbdc::twophase_client>(opts,
                                                         logger,
                                                         wallet_file,
                                                         client_file);
    } else {
        client = std::make_unique<cbdc::atomizer_client>(opts,
                                                         logger,
                                                         wallet_file,
                                                         client_file);
    }

    if(!client->init()) {
        return -1;
    }

    const auto command = std::string(args[4]);
    if(command == "mint") {
        if(!mint_command(*client, args)) {
            return -1;
        }
    } else if(command == "send") {
        if(!send_command(*client, args)) {
            return -1;
        }
    } else if(command == "fan") {
        if(!fan_command(*client, args)) {
            return -1;
        }
    } else if(command == "sync") {
        client->sync();
    } else if(command == "newaddress") {
        newaddress_command(*client);
    } else if(command == "info") {
        const auto balance = client->balance();
        const auto n_txos = client->utxo_count();
        std::cout << "Balance: " << cbdc::client::print_amount(balance)
                  << ", UTXOs: " << n_txos
                  << ", pending TXs: " << client->pending_tx_count()
                  << std::endl;
    } else if(command == "importinput") {
        if(!importinput_command(*client, args)) {
            return -1;
        }
    } else if(command == "confirmtx") {
        if(!confirmtx_command(*client, args)) {
            return -1;
        }
    } else {
        std::cerr << "Unknown command" << std::endl;
    }

    // TODO: check that the send queue has drained before closing
    //       the network. For now, just sleep.
    static constexpr auto shutdown_delay = std::chrono::milliseconds(100);
    std::this_thread::sleep_for(shutdown_delay);

    return 0;
}
// LCOV_EXCL_STOP
