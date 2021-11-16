#!/usr/bin/env python3
# Copyright (c) 2018-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the scantxoutset rpc call."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

from decimal import Decimal
import shutil
import os

def descriptors(out):
    return sorted(u['desc'] for u in out['unspents'])

class ScantxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Mining blocks...")
        self.nodes[0].generate(250)

        addr_P2SH_SEGWIT = self.nodes[0].getnewaddress("", "p2sh-segwit")
        pubk1 = self.nodes[0].getaddressinfo(addr_P2SH_SEGWIT)['pubkey']
        addr_LEGACY = self.nodes[0].getnewaddress("", "legacy")
        pubk2 = self.nodes[0].getaddressinfo(addr_LEGACY)['pubkey']
        addr_BECH32 = self.nodes[0].getnewaddress("", "bech32")
        pubk3 = self.nodes[0].getaddressinfo(addr_BECH32)['pubkey']
        self.nodes[0].sendtoaddress(addr_P2SH_SEGWIT, 0.01)
        self.nodes[0].sendtoaddress(addr_LEGACY, 0.02)
        self.nodes[0].sendtoaddress(addr_BECH32, 0.04)

        #send to child keys of tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK
        self.nodes[0].sendtoaddress("nYxgyQgsm4a6SLiccPQkvHnrLuJqYgdk1n", 0.08) # (m/0'/0'/0')
        self.nodes[0].sendtoaddress("nXVgQeMsb5x5Vbj6vE5XkdgZ3VKfYgY9VA", 0.16) # (m/0'/0'/1')
        self.nodes[0].sendtoaddress("nqnq8VEfnBw2uDS47RmVDUnSUHLzfYMKkQ", 0.32) # (m/0'/0'/1500')
        self.nodes[0].sendtoaddress("ne7MQ3GiCjFvdpXR1iLtJTLZYCPgnCCGsN", 0.64) # (m/0'/0'/0)
        self.nodes[0].sendtoaddress("nb8t3u66GQnML9rVn9akCUnBN75icvtLYz", 1.28) # (m/0'/0'/1)
        self.nodes[0].sendtoaddress("nZL6AqgkZq5EHWHtFiVTBYqkYgSbZTABmM", 2.56) # (m/0'/0'/1500)
        self.nodes[0].sendtoaddress("nXpCEDTAbyZL9Q67FEgSMocQyohPUCi4Qk", 5.12) # (m/1/1/0')
        self.nodes[0].sendtoaddress("nUTXnXzp6FiUDfWBmNZzKtvyj3uNFSy3xu", 10.24) # (m/1/1/1')
        self.nodes[0].sendtoaddress("ncaJaPcKzjwY1AdBvhe94nyX3dam9zGNJU", 20.48) # (m/1/1/1500')
        self.nodes[0].sendtoaddress("nhLgmhBXZgzedPSbsmgSRXW6EpKaK3q74h", 40.96) # (m/1/1/0)
        self.nodes[0].sendtoaddress("nmVKuLKhrN6ajCQcwGh2okUU94oAQsLpTi", 81.92) # (m/1/1/1)
        self.nodes[0].sendtoaddress("nd5Lq2Lk8AwCokaaTvujRq2LzB2dd726Ud", 163.84) # (m/1/1/1500)


        self.nodes[0].generate(1)

        self.log.info("Stop node, remove wallet, mine again some blocks...")
        self.stop_node(0)
        shutil.rmtree(os.path.join(self.nodes[0].datadir, self.chain, 'wallets'))
        self.start_node(0, ['-nowallet'])
        self.import_deterministic_coinbase_privkeys()
        self.nodes[0].generate(110)

        scan = self.nodes[0].scantxoutset("start", [])
        info = self.nodes[0].gettxoutsetinfo()
        assert_equal(scan['success'], True)
        assert_equal(scan['height'], info['height'])
        assert_equal(scan['txouts'], info['txouts'])
        assert_equal(scan['bestblock'], info['bestblock'])

        self.restart_node(0, ['-nowallet'])
        self.log.info("Test if we have found the non HD unspent outputs.")
        assert_equal(self.nodes[0].scantxoutset("start", [ "pkh(" + pubk1 + ")", "pkh(" + pubk2 + ")", "pkh(" + pubk3 + ")"])['total_amount'], Decimal("0.02"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "wpkh(" + pubk1 + ")", "wpkh(" + pubk2 + ")", "wpkh(" + pubk3 + ")"])['total_amount'], Decimal("0.04"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "sh(wpkh(" + pubk1 + "))", "sh(wpkh(" + pubk2 + "))", "sh(wpkh(" + pubk3 + "))"])['total_amount'], Decimal("0.01"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(" + pubk1 + ")", "combo(" + pubk2 + ")", "combo(" + pubk3 + ")"])['total_amount'], Decimal("0.07"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "addr(" + addr_P2SH_SEGWIT + ")", "addr(" + addr_LEGACY + ")", "addr(" + addr_BECH32 + ")"])['total_amount'], Decimal("0.07"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "addr(" + addr_P2SH_SEGWIT + ")", "addr(" + addr_LEGACY + ")", "combo(" + pubk3 + ")"])['total_amount'], Decimal("0.07"))

        self.log.info("Test range validation.")
        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].scantxoutset, "start", [ {"desc": "desc", "range": -1}])
        assert_raises_rpc_error(-8, "Range should be greater or equal than 0", self.nodes[0].scantxoutset, "start", [ {"desc": "desc", "range": [-1, 10]}])
        assert_raises_rpc_error(-8, "End of range is too high", self.nodes[0].scantxoutset, "start", [ {"desc": "desc", "range": [(2 << 31 + 1) - 1000000, (2 << 31 + 1)]}])
        assert_raises_rpc_error(-8, "Range specified as [begin,end] must not have begin after end", self.nodes[0].scantxoutset, "start", [ {"desc": "desc", "range": [2, 1]}])
        assert_raises_rpc_error(-8, "Range is too large", self.nodes[0].scantxoutset, "start", [ {"desc": "desc", "range": [0, 1000001]}])

        self.log.info("Test extended key derivation.")
        # Run various scans, and verify that the sum of the amounts of the matches corresponds to the expected subset.
        # Note that all amounts in the UTXO set are powers of 2 multiplied by 0.01 DOGE, so each amounts uniquely identifies a subset.
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0'/0h/0h)"])['total_amount'], Decimal("0.08"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0'/0'/1h)"])['total_amount'], Decimal("0.16"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0h/0'/1500')"])['total_amount'], Decimal("0.32"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0h/0h/0)"])['total_amount'], Decimal("0.64"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0'/0h/1)"])['total_amount'], Decimal("1.28"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0h/0'/1500)"])['total_amount'], Decimal("2.56"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0'/0h/*h)", "range": 1499}])['total_amount'], Decimal("0.24"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0'/0'/*h)", "range": 1500}])['total_amount'], Decimal("0.56"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0h/0'/*)", "range": 1499}])['total_amount'], Decimal("1.92"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0'/0h/*)", "range": 1500}])['total_amount'], Decimal("4.48"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/0')"])['total_amount'], Decimal("5.12"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/1')"])['total_amount'], Decimal("10.24"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/1500h)"])['total_amount'], Decimal("20.48"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/0)"])['total_amount'], Decimal("40.96"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/1)"])['total_amount'], Decimal("81.92"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/1500)"])['total_amount'], Decimal("163.84"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/0)"])['total_amount'], Decimal("40.96"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo([abcdef88/1/2'/3/4h]tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/1)"])['total_amount'], Decimal("81.92"))
        assert_equal(self.nodes[0].scantxoutset("start", [ "combo(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/1500)"])['total_amount'], Decimal("163.84"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/*')", "range": 1499}])['total_amount'], Decimal("15.36"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/*')", "range": 1500}])['total_amount'], Decimal("35.84"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/*)", "range": 1499}])['total_amount'], Decimal("122.88"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/*)", "range": 1500}])['total_amount'], Decimal("286.72"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/*)", "range": 1499}])['total_amount'], Decimal("122.88"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/*)", "range": 1500}])['total_amount'], Decimal("286.72"))
        assert_equal(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/*)", "range": [1500,1500]}])['total_amount'], Decimal("163.84"))

        # Test the reported descriptors for a few matches
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0h/0'/*)", "range": 1499}])), ["pkh([0c5f9a1e/0'/0'/0]026dbd8b2315f296d36e6b6920b1579ca75569464875c7ebe869b536a7d9503c8c)#dzxw429x", "pkh([0c5f9a1e/0'/0'/1]033e6f25d76c00bedb3a8993c7d5739ee806397f0529b1b31dda31ef890f19a60c)#43rvceed"])
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", [ "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/1/1/0)"])), ["pkh([0c5f9a1e/1/1/0]03e1c5b6e650966971d7e71ef2674f80222752740fc1dfd63bbbd220d2da9bd0fb)#cxmct4w8"])
        assert_equal(descriptors(self.nodes[0].scantxoutset("start", [ {"desc": "combo(tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B/1/1/*)", "range": 1500}])), ['pkh([0c5f9a1e/1/1/0]03e1c5b6e650966971d7e71ef2674f80222752740fc1dfd63bbbd220d2da9bd0fb)#cxmct4w8', 'pkh([0c5f9a1e/1/1/1500]03832901c250025da2aebae2bfb38d5c703a57ab66ad477f9c578bfbcd78abca6f)#vchwd07g', 'pkh([0c5f9a1e/1/1/1]030d820fc9e8211c4169be8530efbc632775d8286167afd178caaf1089b77daba7)#z2t3ypsa'])

        # Check that status and abort don't need second arg
        assert_equal(self.nodes[0].scantxoutset("status"), None)
        assert_equal(self.nodes[0].scantxoutset("abort"), False)

        # Check that second arg is needed for start
        assert_raises_rpc_error(-1, "scanobjects argument is required for the start action", self.nodes[0].scantxoutset, "start")

if __name__ == '__main__':
    ScantxoutsetTest().main()
