#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Copyright (c) 2024 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test the dumptxoutset RPC call.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_jsonrpc,
    start_node,
)


class DumptxoutsetTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.is_network_split = False

    def run_test(self):
        """Test basic dumptxoutset functionality."""
        node = self.nodes[0]

        # Mine some blocks so there are UTXOs to dump
        node.generate(110)

        # Determine the output path inside the node's datadir
        datadir = os.path.join(self.options.tmpdir, "node0")
        out_path = os.path.join(datadir, "utxos.dat")
        temp_path = out_path + ".incomplete"

        # Call dumptxoutset
        result = node.dumptxoutset(out_path)

        # Validate return fields
        assert_equal(result['base_height'], 110)
        assert_equal(len(result['base_hash']), 64)
        assert_equal(result['path'], out_path)
        assert_greater_than(result['coins_written'], 0)
        # 110 coinbase transactions = 110 UTXOs (one per block)
        assert_equal(result['coins_written'], 110)

        # The final file should exist
        assert os.path.exists(out_path), "snapshot file was not created"

        # The temporary (.incomplete) file should have been renamed away
        assert not os.path.exists(temp_path), ".incomplete file still present"

        # File must be non-empty
        assert_greater_than(os.path.getsize(out_path), 0)

        # Calling again with the same path should fail
        assert_raises_jsonrpc(
            -8,
            "already exists",
            node.dumptxoutset,
            out_path,
        )

        # Passing a relative path returns an absolute path in the result
        result2 = node.dumptxoutset("utxos2.dat")
        assert os.path.isabs(result2['path'])
        assert result2['path'].endswith("utxos2.dat")
        assert os.path.exists(result2['path'])

        print("dumptxoutset tests passed")


if __name__ == '__main__':
    DumptxoutsetTest().main()
