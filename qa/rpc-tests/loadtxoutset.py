#!/usr/bin/env python3
# Copyright (c) 2024 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test the loadtxoutset RPC call.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_jsonrpc,
    start_node,
)


class LoadtxoutsetTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.is_network_split = False

    def run_test(self):
        node = self.nodes[0]

        node.generate(110)
        datadir = os.path.join(self.options.tmpdir, "node0")
        snapshot_path = os.path.join(datadir, "utxos-load.dat")

        dump_result = node.dumptxoutset(snapshot_path)
        snapshot_info = node.gettxoutsetinfo()

        assert_equal(dump_result["base_height"], 110)
        assert_equal(snapshot_info["hash_serialized_2"], dump_result["txoutset_hash"])

        node.generate(5)
        assert_equal(node.getblockcount(), 115)

        assert_raises_jsonrpc(
            -8,
            "Snapshot content hash mismatch",
            node.loadtxoutset,
            snapshot_path,
            "00" * 32,
        )

        load_result = node.loadtxoutset(snapshot_path, dump_result["txoutset_hash"])

        assert_equal(load_result["coins_loaded"], dump_result["coins_written"])
        assert_equal(load_result["base_height"], dump_result["base_height"])
        assert_equal(load_result["base_hash"], dump_result["base_hash"])
        assert_equal(load_result["path"], snapshot_path)

        restored_info = node.gettxoutsetinfo()
        assert_equal(node.getblockcount(), 110)
        assert_equal(restored_info["bestblock"], snapshot_info["bestblock"])
        assert_equal(restored_info["transactions"], snapshot_info["transactions"])
        assert_equal(restored_info["txouts"], snapshot_info["txouts"])
        assert_equal(restored_info["hash_serialized_2"], snapshot_info["hash_serialized_2"])


if __name__ == '__main__':
    LoadtxoutsetTest().main()
