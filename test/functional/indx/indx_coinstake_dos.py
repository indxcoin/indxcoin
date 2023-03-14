#!/usr/bin/env python3

import time

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    create_tx_with_script,
    script_BIP34_coinbase_height
)
from test_framework.key import ECKey
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    ser_uint256
)
from test_framework.p2p import P2PDataStore
from test_framework.script import (
    CScript,
    OP_CHECKSIG,
    OP_TRUE,
    SIGHASH_ALL,
    LegacySignatureHash,
)
from test_framework.test_framework import BitcoinTestFramework


class CoinstakeDoS(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]  # convenience reference to the node

        self.bootstrap_p2p()  # Add one p2p connection to the node

        self.block_heights = {}
        self.coinbase_key = ECKey()
        self.coinbase_key.generate()
        self.coinbase_pubkey = self.coinbase_key.get_pubkey().get_bytes()
        self.tip = None
        self.blocks = {}
        self.genesis_hash = int(self.nodes[0].getbestblockhash(), 16)
        self.block_heights[self.genesis_hash] = 0
        self.spendable_outputs = []

        # Mine 2200 blocks to end proof-of-work mining
        self.mine_pow_blocks()

        # Create invalid coinstake and block with this coinstake
        stake = self.get_spendable_output()
        coinstake = self.create_pos_coinstake(stake, self.tip.nTime + 24 * 60 * 60, prevN=1000000000)
        block = self.mine_pos_block(coinstake=coinstake)


        try:
            self.send_blocks([block], success=False, reconnect=True)
        except ConnectionRefusedError:
            print("Can not connect to node, it crashed")

    # Helper methods
    ################

    def create_pos_coinbase(self, height):
        coinbase = CTransaction()
        coinbase.vin.append(CTxIn(COutPoint(0, 0xffffffff),
                            script_BIP34_coinbase_height(height), 0xffffffff))
        coinbaseoutput = CTxOut()
        coinbaseoutput.nValue = 0
        coinbaseoutput.scriptPubKey = CScript([])
        coinbase.vout = [coinbaseoutput]
        coinbase.rehash()
        return coinbase

    def create_pos_coinstake(self, stake, block_time, transfer_value=10, prevN = 0):
        tx = CTransaction()
        tx.nVersion = 2
        tx.nTime = block_time
        tx.vin.append(CTxIn(COutPoint(stake.sha256, prevN)))
        tx.vout.append(CTxOut(0, CScript([])))
        tx.vout.append(CTxOut(transfer_value, CScript(
            [self.coinbase_pubkey, OP_CHECKSIG])))
        self.sign_tx(tx, stake)
        tx.rehash()
        return tx

    def mine_pos_block(self, stake=None, coinbase=None, coinstake=None, extra_txs=None):
        block_time = self.tip.nTime + 24 * 60 * 60
        height = self.block_heights[self.tip.sha256] + 1

        if not coinbase:
            coinbase = self.create_pos_coinbase(height)
        if not coinstake:
            if not stake:
                stake = self.get_spendable_output()
            coinstake = self.create_pos_coinstake(stake, block_time)

        block = create_block(self.tip.sha256, coinbase, block_time, version=3)

        # add coinstake
        block.vtx.extend([coinstake])

        # add extra txs
        if extra_txs:
            block.vtx.extend(extra_txs)

        # set hashMerkleRoot and find a valid nonce.
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        # sign block
        block.vchBlockSig = self.coinbase_key.sign_ecdsa(
            ser_uint256(block.sha256))

        self.tip = block
        self.block_heights[block.sha256] = height
        return block

    def mine_pow_block(self, coinbase_value=0, version=2):
        if self.tip is None:
            base_block_hash = self.genesis_hash
            block_time = int(time.time())
        else:
            base_block_hash = self.tip.sha256
            block_time = self.tip.nTime + 600

        # Create the coinbase
        height = self.block_heights[base_block_hash] + 1
        coinbase = create_coinbase(
            height, self.coinbase_pubkey, nValue=coinbase_value)
        block = create_block(base_block_hash, coinbase,
                             block_time, version=version)

        # Block is created. Find a valid nonce.
        block.solve()
        self.tip = block
        self.block_heights[block.sha256] = height
        return block

    def mine_pow_blocks(self):
        blocks = []
        for i in range(2200):
            blocks.append(self.mine_pow_block(
                coinbase_value=500000 if i < 2000 else 0))
            self.save_spendable_output()
            if len(blocks) >= 500:
                self.send_blocks(blocks)
                blocks = []
        if len(blocks) >= 0:
            self.send_blocks(blocks)

    # sign a transaction, using the key we know about
    # this signs input 0 in tx, which is assumed to be spending output 0 in spend_tx
    def sign_tx(self, tx, spend_tx, in_n=0, out_n=0):
        scriptPubKey = bytearray(spend_tx.vout[out_n].scriptPubKey)
        if (scriptPubKey == OP_TRUE):  # an anyone-can-spend
            tx.vin[in_n].scriptSig = CScript()
        else:
            (sighash, err) = LegacySignatureHash(
                spend_tx.vout[out_n].scriptPubKey, tx, 0, SIGHASH_ALL)
            tx.vin[in_n].scriptSig = CScript(
                [self.coinbase_key.sign_ecdsa(sighash) + bytes(bytearray([SIGHASH_ALL]))])
        tx.rehash()

    # save the current tip so it can be spent by a later block
    def save_spendable_output(self):
        self.log.debug(f"saving spendable output {self.tip.vtx[0]}")
        self.spendable_outputs.append(self.tip)

    # get an output that we previously marked as spendable
    def get_spendable_output(self):
        self.log.debug(
            f"getting spendable output {self.spendable_outputs[0].vtx[0]}")
        return self.spendable_outputs.pop(0).vtx[0]

    def bootstrap_p2p(self, timeout=10):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        self.helper_peer = self.nodes[0].add_p2p_connection(P2PDataStore())
        self.helper_peer.wait_for_getheaders(timeout=timeout)

    def reconnect_p2p(self, timeout=60):
        """Tear down and bootstrap the P2P connection to the node.

        The node gets disconnected several times in this test. This helper
        method reconnects the p2p and restarts the network thread."""
        self.nodes[0].disconnect_p2ps()
        self.bootstrap_p2p(timeout=timeout)

    def send_blocks(self, blocks, success=True, reject_reason=None, force_send=False, reconnect=False, timeout=960):
        """Sends blocks to test node. Syncs and verifies that tip has advanced to most recent block.

        Call with success = False if the tip shouldn't advance to the most recent block."""
        self.nodes[0].setmocktime(blocks[-1].nTime)
        self.helper_peer.send_blocks_and_test(
            blocks, self.nodes[0], success=success, reject_reason=reject_reason, force_send=force_send, timeout=timeout, expect_disconnect=reconnect)
        if reconnect:
            self.reconnect_p2p(timeout=timeout)


if __name__ == '__main__':
    CoinstakeDoS().main()
