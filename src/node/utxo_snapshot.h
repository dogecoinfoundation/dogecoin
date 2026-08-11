// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_UTXO_SNAPSHOT_H
#define BITCOIN_NODE_UTXO_SNAPSHOT_H

#include <array>
#include <cstdint>
#include <stdexcept>
#include <uint256.h>
#include <serialize.h>

//! Magic bytes written at the start of every UTXO snapshot file.
//! Used to detect files that are not UTXO snapshots.
static const std::array<uint8_t, 5> SNAPSHOT_MAGIC_BYTES = {{'u', 't', 'x', 'o', 0xff}};

//! Current UTXO snapshot file format version.
static const uint16_t SNAPSHOT_VERSION = 1;

//! Metadata describing a serialized version of a UTXO set from which an
//! assumeutxo CChainState can be constructed.
//! All metadata fields come from an untrusted file, so must be validated
//! before being used.
class SnapshotMetadata
{
public:
    //! The network magic (pchMessageStart) identifying the chain this snapshot
    //! belongs to. Used to detect cross-chain load attempts.
    uint8_t m_network_magic[4];

    //! The hash of the block that reflects the tip of the chain for the
    //! UTXO set contained in this snapshot.
    uint256 m_base_blockhash;

    //! The number of coins in the UTXO set contained in this snapshot. Used
    //! during snapshot load to estimate progress of UTXO set reconstruction.
    uint64_t m_coins_count = 0;

    //! The number of transactions in the chain up to and including the base
    //! block; used to estimate IBD progress for the loaded chainstate.
    unsigned int m_nchaintx = 0;

    SnapshotMetadata() { memset(m_network_magic, 0, sizeof(m_network_magic)); }

    SnapshotMetadata(
        const uint8_t* network_magic,
        const uint256& base_blockhash,
        uint64_t coins_count,
        unsigned int nchaintx) :
            m_base_blockhash(base_blockhash),
            m_coins_count(coins_count),
            m_nchaintx(nchaintx)
    {
        memcpy(m_network_magic, network_magic, sizeof(m_network_magic));
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        if (!ser_action.ForRead()) {
            // Serialize: write magic bytes and version first
            std::array<uint8_t, 5> magic = SNAPSHOT_MAGIC_BYTES;
            READWRITE(FLATDATA(magic));
            uint16_t version = SNAPSHOT_VERSION;
            READWRITE(version);
            READWRITE(FLATDATA(m_network_magic));
        } else {
            // Deserialize: read and validate magic bytes and version
            std::array<uint8_t, 5> magic;
            READWRITE(FLATDATA(magic));
            if (magic != SNAPSHOT_MAGIC_BYTES) {
                throw std::ios_base::failure(
                    "Invalid UTXO snapshot magic bytes. "
                    "Is this really a snapshot file?");
            }
            uint16_t version;
            READWRITE(version);
            if (version != SNAPSHOT_VERSION) {
                throw std::ios_base::failure(
                    "Unsupported UTXO snapshot version");
            }
            READWRITE(FLATDATA(m_network_magic));
        }
        READWRITE(m_base_blockhash);
        READWRITE(m_coins_count);
        READWRITE(m_nchaintx);
    }
};

#endif // BITCOIN_NODE_UTXO_SNAPSHOT_H
