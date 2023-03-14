#!/usr/bin/env python3

import time
from pprint import pprint
from copy import copy, deepcopy

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    create_tx_with_script,
    script_BIP34_coinbase_height
)
from test_framework.wallet_util import (
    get_generate_key,
)
from test_framework.script_util import (
    keyhash_to_p2pkh_script,
    scripthash_to_p2sh_script,
    key_to_p2pkh_script,
    script_to_p2sh_script,
    key_to_p2sh_p2wpkh_script,
    program_to_witness_script,
    script_to_p2wsh_script,
    key_to_p2wpkh_script,
    script_to_p2sh_p2wsh_script,
    check_key,
    check_script,
)
from test_framework.util import (
    hex_str_to_bytes,
    find_output,
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
    CScriptOp,
    OP_CHECKSIG,
    OP_TRUE,
    SIGHASH_ALL,
    LegacySignatureHash,
    FindAndDelete,
)
from test_framework.test_framework import BitcoinTestFramework


class BlockDoS(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):

        self.log.info("Starting POS Block DOS test")
        node = self.nodes[0]  # convenience reference to the node

        ##self.log.info("Create Wallet")
        ##node.createwallet(wallet_name="wallet")
        ##wallet = node.get_wallet_rpc("wallet")

        ###self.log.info("Create Address")
        ###self.address = wallet.getnewaddress()
        ###self.address_pubkey = wallet.getaddressinfo(self.address)['pubkey']


        self.bootstrap_p2p()  # Add one p2p connection to the node

        self.block_heights = {}
        ###self.coinbase_key = ECKey()
        ###self.coinbase_key.generate()
        ###self.coinbase_pubkey = self.coinbase_key.get_pubkey().get_bytes()

        ##self.coinbase_base = get_generate_key()
        self.coinbase_key = ECKey()
        self.coinbase_key.set((1).to_bytes(32, 'big'), True)
        ##pub_key = self.coinbase_key.get_pubkey()

        ##self._priv_key.set((1).to_bytes(32, 'big'), True)
        ##pub_key = self._priv_key.get_pubkey()
        ##self.scriptPubKey = bytes(CScript([pub_key.get_bytes(), OP_CHECKSIG]))


        self.tip = None
        self.blocks = {}
        self.genesis_hash = int(self.nodes[0].getbestblockhash(), 16)
        self.block_heights[self.genesis_hash] = 0
        self.spendable_outputs = []

        
        # Mine 2200 blocks to end proof-of-work mining
        self.log.info("Mine 2200 blocks to end proof-of-work mining")
        self.mine_pow_blocks()

        # Create PoS block
        self.log.info("Create PoS block")
        block = self.mine_pos_block()
        self.update_node_time(block)
        self.send_blocks([block], True, None, True)
        block_hash = block.sha256

        # add new, empty transaction to block
        self.log.info("add new, empty transaction to block")
        txin = self.get_spendable_output()
        emptytx = CTransaction()
        emptytx.nVersion = 3
        block.nVersion = 4
        block.vtx.append(emptytx)

        
        
        self.log.info("sending 100 valid blocks for the same height (tip)")
        for i in range(100):
            # create new, unique transaction and replace it in block
            new_transaction = create_tx_with_script(txin.vtx[0], n=0, amount=i + 1, script_pub_key=self.coinbase_key.get_pubkey().get_bytes())
            new_transaction.nVersion = 3
            self.sign_tx(new_transaction, txin.vtx[0], out_n=0)
            block.vtx[-1] = new_transaction

            block.hashMerkleRoot = block.calc_merkle_root()
            block.solve()

            # sign block
            block.vchBlockSig = self.coinbase_key.sign_ecdsa(ser_uint256(block.sha256))
            self.update_node_time()
            self.send_blocks([block], False, 'prevout-not-in-chain', True)

        # mine one more valid block to check if previous block was kept in memory 
        self.log.info("mining one more valid block")
        self.block_heights[block.sha256] = self.block_heights[block_hash]
        self.tip = block

        block = self.mine_pos_block()
        self.update_node_time()
        self.send_blocks([block], True, None, True)



    # Helper methods
    ################

    def update_node_time(self, block=None):
        for i in range(self.num_nodes):
            if self.block_heights[int(self.nodes[0].getbestblockhash(), 16)] + 1 > 2200 and  block != None:
                self.nodes[i].setmocktime(int(block.nTime))
            elif self.block_heights[int(self.nodes[0].getbestblockhash(), 16)] + 1 <= 2200:
                if int(self.nodes[0].getbestblockhash(), 16) == self.genesis_hash :
                    self.nodes[i].setmocktime(int(time.time()) + 600)
                else:
                    self.nodes[i].setmocktime(int(self.nodes[0].getblock(self.nodes[0].getbestblockhash())['time'] + 120))
            


    def create_pos_coinbase(self, height):
        coinbase = CTransaction()
        coinbase.nVersion = 3
        coinbase.vin.append(CTxIn(COutPoint(0, 0xffffffff),
                            script_BIP34_coinbase_height(height), 0xffffffff))
        coinbaseoutput = CTxOut()
        coinbaseoutput.nValue = 0
        coinbaseoutput.scriptPubKey = CScript([])
        coinbase.vout = [coinbaseoutput]
        coinbase.rehash()
        return coinbase

    def create_pos_coinstake(self, stake, block_time, transfer_value=50000000000000):
        tx = CTransaction()
        tx.nVersion = 3
        tx.nTime = block_time
        tx.vin.append(CTxIn(COutPoint(stake.vtx[0].sha256, 0), b'' , nSequence=4294967295))  
        tx.vout.append(CTxOut())
        ##PUBKEY
        tx.vout.append(CTxOut(transfer_value, CScript([ self.coinbase_key.get_pubkey().get_bytes() , OP_CHECKSIG])))

        tx.calc_sha256()
        self.sign_tx(tx, stake.vtx[0])
        tx.rehash()
        return tx

    def mine_pos_block(self, stake=None, coinbase=None, coinstake=None, extra_txs=None):
        block_time = self.tip.nTime + 60
        height = self.block_heights[self.tip.sha256] + 1

        if not stake:
            stake = self.get_spendable_output()
        if not coinbase:
            coinbase = self.create_pos_coinbase(height)
            coinbase.nTime = block_time
            coinbase.rehash()
        if not coinstake:
            coinstake = self.create_pos_coinstake(stake, block_time)

        block = create_block(self.tip.sha256, coinbase, block_time, version=4)

        # add coinstake
        block.vtx.extend([coinstake])

        # add extra txs
        if extra_txs is not None:
            block.vtx.extend(extra_txs)

        # set hashMerkleRoot and find a valid nonce.
        block.nVersion = 4
        block.nNonce = 0
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        # sign block
        der_sig = self.coinbase_key.sign_ecdsa(ser_uint256(block.sha256))
        block.vchBlockSig =    der_sig 

        ##self.log.info("POS Block: " + str(block))
        self.tip = block
        self.block_heights[block.sha256] = height
        return block

    def mine_pow_block(self, coinbase_value=0, version=1):
        if self.tip is None:
            base_block_hash = self.genesis_hash
            block_time = int(time.time())
        else:
            base_block_hash = self.tip.sha256
            block_time = self.tip.nTime + 120

        # Create the coinbase
        height = self.block_heights[base_block_hash] + 1
        coinbase = create_coinbase(
            height, pubkey=self.coinbase_key.get_pubkey().get_bytes() , nValue=coinbase_value) 

        block = create_block(base_block_hash, coinbase,
                             block_time, version=version)

        # Block is created. Find a valid nonce.
        block.nVersion = 1
        block.nNonce = 1
        block.solve()
        self.tip = block
        self.block_heights[block.sha256] = height
        return block

    def mine_pow_blocks(self):
        blocks = []
        for i in range(2200):
            blocks.append(self.mine_pow_block(
                coinbase_value=50000000000000 if i < 2000 else 0))
            self.save_spendable_output()
            if len(blocks) >= 500:
                self.send_blocks(blocks, True, None, True)
                blocks = []
        if len(blocks) >= 0:
            self.send_blocks(blocks, True, None, True)

    # sign a transaction, using the key we know about
    # this signs input 0 in tx, which is assumed to be spending output 0 in spend_tx
    def sign_tx(self, tx, spend_tx, in_n=0, out_n=0):
        scriptPubKey =  spend_tx.vout[out_n].scriptPubKey
        if (scriptPubKey == OP_TRUE):  # an anyone-can-spend
            self.log.info("anyone-can-spend")
            tx.vin[in_n].scriptSig = CScript()
        else:
            self.log.info("LegacySignatureHash")
            (sighash, err) = LegacySignatureHash(scriptPubKey, tx, 0, SIGHASH_ALL)
            sig = b''
            while not len(sig) == 71:
                sig = self.coinbase_key.sign_ecdsa(sighash) + bytes(bytearray([SIGHASH_ALL]))
            
            scriptSig = CScript([ sig ])
            tx.vin[in_n].scriptSig = scriptSig

        tx.rehash()

    # save the current tip so it can be spent by a later block
    def save_spendable_output(self):
        self.log.debug(f"saving spendable output {self.tip.vtx[0]}")
        self.spendable_outputs.append(self.tip)

    # get an output that we previously marked as spendable
    def get_spendable_output(self):
        ##self.log.info(f"getting spendable output {self.spendable_outputs[0].vtx[0]}")
        ##self.log.info(f"getting spendable output {self.spendable_outputs[0]}")
        ###return self.spendable_outputs.pop(0).vtx[0]
        return self.spendable_outputs.pop(0)

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
        ##self.nodes[0].setmocktime(blocks[-1].nTime)
        for i in blocks:
            block = []
            block.append(i)
            self.update_node_time()
            self.helper_peer.send_blocks_and_test(
                block, self.nodes[0], success=success, reject_reason=reject_reason, force_send=force_send, timeout=timeout, expect_disconnect=reconnect)

            if reconnect:
                self.reconnect_p2p(timeout=timeout)


if __name__ == '__main__':
    BlockDoS().main()
