#!/usr/bin/env python3

import time
import copy
from pprint import pprint


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


class BlockPOSFork(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):

        self.log.info("Starting POS Block FORK Test")
        node = self.nodes[0]  # convenience reference to the node

        # disconnect nodes before p2p connection
        self.disconnect_nodes(0, 1)
        
        
        # Add one p2p connection to the node0
        self.helper_peer = self.nodes[0].add_p2p_connection(P2PDataStore())
        self.helper_peer.wait_for_getheaders()
        
        
        # reconnect nodes for pow mining
        self.connect_nodes(0, 1)


        self.block_heights = {}
        self.coinbase_key = ECKey()
        self.coinbase_key.set((1).to_bytes(32, 'big'), True)


        self.tip = None
        self.blocks = {}
        self.genesis_hash = int(self.nodes[0].getbestblockhash(), 16)
        self.block_heights[self.genesis_hash] = 0
        self.spendable_outputs = []

        
        # Mine 2200 blocks to end proof-of-work mining
        self.log.info("Mine 2200 blocks to end proof-of-work mining")
        self.mine_pow_blocks()

        ## disconnect node0 connect node1
        self.nodes[0].disconnect_p2ps()
        self.helper_peer = self.nodes[1].add_p2p_connection(P2PDataStore())
        self.helper_peer.wait_for_getheaders()

        #sync nodes
        self.log.info("Sync Node 1 and Node 0")
        self.connect_nodes(0, 1)
        self.sync_blocks(self.nodes[0:1])
        self.wait_until(lambda: self.nodes[1].getblockcount() >= 2200)

        # disconnect nodes for POS blocks
        self.disconnect_nodes(0, 1)


        ## Create extra transaction
        self.log.info("Create extra transaction")
        txin = self.get_spendable_output()
        new_transaction = create_tx_with_script(txin.vtx[0], n=0, amount=49999998000000, script_pub_key=self.coinbase_key.get_pubkey().get_bytes())
        new_transaction.nVersion = 3
        self.sign_tx(new_transaction, txin.vtx[0], out_n=0)

        # Create duplicate PoS kernels
        self.log.info("Create duplicate PoS kernels")
        self.posblocks = []
        self.posblocks = self.mine_pos_block(extra_txs=new_transaction)
        self.update_node_time(self.posblocks[0])

        ## disconnect node1 connect node0
        self.nodes[1].disconnect_p2ps()
        self.helper_peer = self.nodes[0].add_p2p_connection(P2PDataStore())
        self.helper_peer.wait_for_getheaders()

        self.send_blocks([self.posblocks[0]], True, None, True)

        ## disconnect node0 connect node1
        self.nodes[0].disconnect_p2ps()
        self.helper_peer = self.nodes[1].add_p2p_connection(P2PDataStore())
        self.helper_peer.wait_for_getheaders()

        self.send_blocks([self.posblocks[1]], True, None, True, nodeid=1)
        block_hash = self.posblocks[0].sha256

        # Create one more PoS block on node0
        self.log.info("Create one more PoS block on node0")
        ## disconnect node0 connect node1
        self.nodes[1].disconnect_p2ps()
        self.helper_peer = self.nodes[0].add_p2p_connection(P2PDataStore())
        self.helper_peer.wait_for_getheaders()

        self.posblocks = []
        self.posblocks = self.mine_pos_block(savestake=True)
        self.update_node_time(self.posblocks[0])
        self.send_blocks([self.posblocks[0]], True, None, True)
        block_hash = self.posblocks[0].sha256


        self.log.info("Sync the two nodes")
        #sync nodes
        self.connect_nodes(0, 1)
        self.sync_blocks(self.nodes[0:1])
        self.wait_until(lambda: self.nodes[0].getblockcount() >= 2202)
        ##self.wait_until(lambda: self.nodes[1].getblockcount() >= 2202)

        # Create one more PoS block on node0
        self.log.info("Send previous kernel PoS block to node0")
        ## disconnect node0 connect node1
        self.nodes[1].disconnect_p2ps()
        self.helper_peer = self.nodes[0].add_p2p_connection(P2PDataStore())
        self.helper_peer.wait_for_getheaders()

        self.posblocks = []
        self.posblocks = self.mine_pos_block(uselstake=True)
        self.update_node_time(self.posblocks[0])
        self.send_blocks([self.posblocks[0]], False, None, True)
        block_hash = self.posblocks[0].sha256

        time.sleep(300)


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

    def mine_pos_block(self, stake=None, coinbase=None, coinstake=None, extra_txs=None, savestake=False, uselstake=False):
        block_time = self.tip.nTime + 60
        height = self.block_heights[self.tip.sha256] + 1

        if not stake:
            stake = self.get_spendable_output()
            if savestake == True:
                self.stakelater = copy.deepcopy(stake)
            if uselstake == True:
                stake = copy.deepcopy(self.stakelater)
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
            blocks = {}
            # set hashMerkleRoot and find a valid nonce.
            block.nVersion = 4
            block.nNonce = 0
            block.hashMerkleRoot = block.calc_merkle_root()
            block.solve()
            der_sig = self.coinbase_key.sign_ecdsa(ser_uint256(block.sha256))
            block.vchBlockSig =    der_sig
            self.log.debug("Block : " + str(block))
            blocks[0] = block
            
            blockv2 = copy.deepcopy(block)
            blockv2.vtx.extend([extra_txs])
            blockv2.hashMerkleRoot = blockv2.calc_merkle_root()
            blockv2.solve()
            der_sig = self.coinbase_key.sign_ecdsa(ser_uint256(blockv2.sha256))
            blockv2.vchBlockSig =    der_sig
            self.log.debug("Blockv2 : " + str(blockv2))
            blocks[1] = blockv2
            
            self.tip = block
            self.block_heights[block.sha256] = height
            
            return blocks

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
        blocks = {}
        blocks[0] = block
        return blocks

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
            self.log.debug("anyone-can-spend")
            tx.vin[in_n].scriptSig = CScript()
        else:
            self.log.debug("LegacySignatureHash")
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
        self.log.debug(f"getting spendable output {self.spendable_outputs[0]}")
        
        return self.spendable_outputs.pop(0)

    def bootstrap_p2p(self, timeout=60):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        self.helper_peer = self.nodes[0].add_p2p_connection(P2PDataStore())
        self.helper_peer.wait_for_getheaders(timeout=timeout)
        self.helper_peer2 = self.nodes[1].add_p2p_connection(P2PDataStore())
        self.helper_peer2.wait_for_getheaders(timeout=timeout)

    def reconnect_p2p(self, timeout=60):
        """Tear down and bootstrap the P2P connection to the node.

        The node gets disconnected several times in this test. This helper
        method reconnects the p2p and restarts the network thread."""
        self.nodes[0].disconnect_p2ps()
        self.nodes[1].disconnect_p2ps()
        self.bootstrap_p2p(timeout=timeout)

    def send_blocks(self, blocks, success=True, reject_reason=None, force_send=False, reconnect=False, timeout=960, nodeid=0):
        """Sends blocks to test node. Syncs and verifies that tip has advanced to most recent block.

        Call with success = False if the tip shouldn't advance to the most recent block."""
        
        for i in blocks:
            block = []
            block.append(i)
            self.update_node_time()
            self.helper_peer.send_blocks_and_test(
                block, self.nodes[nodeid], success=success, reject_reason=reject_reason, force_send=force_send, timeout=timeout, expect_disconnect=reconnect)



if __name__ == '__main__':
    BlockPOSFork().main()
