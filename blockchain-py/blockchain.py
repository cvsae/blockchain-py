import sys
import pickle
from collections import defaultdict


from block import Block
from db import Bucket
from transaction import CoinbaseTx
from utils import ContinueIt, BreakIt, GetAppDir
from errors import NotFoundTransaction




class Blockchain(object):
    """ Blockchain keeps a sequence of Blocks

    Attributes:
        _tip (bytes): Point to the latest hash of block.
        _bucket (dict): bucket of DB 
    """
    latest = 'l'
    db_file = GetAppDir() + str(r'\blockchain.db')
    block_bucket = 'blocks'
    genesis_coinbase_data = 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'

    def __init__(self):
        self._bucket = Bucket(Blockchain.db_file, Blockchain.block_bucket)

        try:
            self._tip = self._bucket.get('l')
        except KeyError:
            self._tip = None
        

    def _block_put(self, block):

        for tx in block._tx_lst:
            if not self.verify_transaction(tx):
                utils.logg('Verify transactions faild, block contains one or more txs wich cant be verified')
                return False



        self._bucket.put(block.hash, block.serialize())
        self._bucket.put('l', block.hash)
        self._tip = block.hash

        
        return self._bucket.commit()

    

    def find_unspent_transactions(self, pubkey_hash):
        # Returns a list of transactions containing unspent outputs
        spent_txo = defaultdict(list)
        unspent_txs = []
        for block in self.blocks:
            for tx in block.transactions:

                if not isinstance(tx, CoinbaseTx):
                    for vin in tx.vin:
                        if vin.uses_key(pubkey_hash):
                            tx_id = vin.tx_id
                            spent_txo[tx_id].append(vin.vout)

                tx_id = tx.ID
                try:
                    for out_idx, out in enumerate(tx.vout):
                        # Was the output spent?
                        if spent_txo[tx_id]:
                            for spent_out in spent_txo[tx_id]:
                                if spent_out == out_idx:
                                    raise ContinueIt

                        if out.is_locked_with_key(pubkey_hash):
                            unspent_txs.append(tx)
                except ContinueIt:
                    pass

        return unspent_txs

    def find_utxo(self):
        # Finds all unspent transaction outputs
        utxo = defaultdict(list)
        spent_txos = defaultdict(list)

        for block in self.blocks:
            for tx in block.transactions:

                try:
                    for out_idx, out in enumerate(tx.vout):
                        # Was the output spent?
                        if spent_txos[tx.ID]:
                            for spent_out in spent_txos[tx.ID]:
                                if spent_out == out_idx:
                                    raise ContinueIt

                        utxo[tx.ID].append(out)
                except ContinueIt:
                    pass

                if not isinstance(tx, CoinbaseTx):
                    for vin in tx.vin:
                        spent_txos[vin.tx_id].append(vin.vout)

        return utxo

    @property
    def blocks(self):
        current_tip = self._tip
        while True:
            if not current_tip:
                # Encounter genesis block
                break
            encoded_block = self._bucket.get(current_tip)
            block = pickle.loads(encoded_block)
            yield block
            current_tip = block.prev_block_hash

    def haveBlock(self, block_hash):
        for block in self.blocks:
            if block.hash == block_hash:
                return True 
        return False



    def getBlock(self, block_hash):
        if self.haveBlock(block_hash):
            for block in self.blocks:
                if block.hash == block_hash:
                    return block 
        return None

    def find_transaction(self, ID):
        # finds a transaction by its ID
        for block in self.blocks:
            for tx in block.transactions:
                if tx.ID == ID:
                    return tx
        # return None
        raise NotFoundTransaction

    def sign_transaction(self, tx, priv_key):
        prev_txs = {}
        for vin in tx.vin:
            prev_tx = self.find_transaction(vin.tx_id)
            prev_txs[prev_tx.ID] = prev_tx

        tx.sign(priv_key, prev_txs)

    def verify_transaction(self, tx):
        if tx.isCoinBase():
            return True

        prev_txs = {}
        for vin in tx.vin:
            prev_tx = self.find_transaction(vin.tx_id)
            prev_txs[prev_tx.ID] = prev_tx

        return tx.verify(prev_txs)
