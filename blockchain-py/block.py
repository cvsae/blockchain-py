import time
import hashlib
import binascii
import pickle

import utils
from pow import Pow
from merkle_tree import MerkleTree


class Block(object):
    """ Represents a new Block object.

    Args:
        transaction_lst (list): List of transaction.
        prev_block_hash (string): Hash of the previous Block. 

    Attributes:
        _timestamp (bytes): Creation timestamp of Block.
        _tx_lst (list): List of transaction.
        _prev_block_hash (bytes): Hash of the previous Block.
        _hash (bytes): Hash of the current Block.
        _nonce (int): A 32 bit arbitrary random number that is typically used once.
    """

    def __init__(self, transaction_lst):
        self._timestamp = None
        self._tx_lst = transaction_lst
        self._prev_block_hash = None
        self._hash = None
        self._nonce = None
        self._bits = None 

    def __repr__(self):
        return 'Block(timestamp={0!r}, tx_lst={1!r}, prev_block_hash={2!r}, hash={3!r}, nonce={4!r}, bits={5!r})'.format(
            self._timestamp, self._tx_lst, self._prev_block_hash, self._hash, self._nonce, self._bits)

    @property
    def hash(self):
        return utils.decode(self._hash)

    def getHash(self):
        data_lst = [self.prev_block_hash,
                    self.hash_transactions(),
                    self.timestamp,
                    str(self.bits),
                    str(self._nonce)]
        data = utils.encode(''.join(data_lst))
        hash_hex = utils.sum256_hex(data)

        self._hash = utils.encode(hash_hex)

        return hash_hex

    @property
    def prev_block_hash(self):
        return utils.decode(self._prev_block_hash)

    @prev_block_hash.setter
    def prev_block_hash(self, r_value):
        self._prev_block_hash = utils.encode(r_value)

    @property
    def timestamp(self):
        return str(self._timestamp)

    @property
    def bits(self):
        return self._bits

    @bits.setter
    def bits(self, r_value):
        self._bits = r_value

    @timestamp.setter
    def timestamp(self, r_value):
        self._timestamp = utils.encode(str(r_value))

    @property
    def nonce(self):
        return str(self._nonce)

    @nonce.setter
    def nonce(self, value):
        self._nonce = value

    @property
    def transactions(self):
        return self._tx_lst


    def pow_of_block(self):
        # Makes the proof of work of the current Block
        pow = Pow(self)
        nonce, hash = pow.run()
        self._nonce, self._hash = nonce, utils.encode(hash)
        return self

    def hash_transactions(self):
        # return a hash of the transactions in the block
        tx_byte_lst = []

        for tx in self._tx_lst:
            tx_byte_lst.append(tx.to_bytes())

        m_tree = MerkleTree(tx_byte_lst)
        return utils.decode(binascii.hexlify(m_tree.root_hash))

    def CheckBlock(self):
        # Size limits
        if len(self._tx_lst) == 0 or len(self._tx_lst) > 1000000000:
            print("CheckBlock() : size limits failed")
            return False

        # First transaction must be coinbase, the rest must not be
        if len(self._tx_lst) == 0 or not self._tx_lst[0].isCoinBase():
            print("CheckBlock() : first tx is not coinbase")
            return False

        for i in range(1, len(self._tx_lst)):
            if self._tx_lst[i].isCoinBase():
                print("CheckBlock() : more than one coinbase")
                return False

        # Check transactions
        for tx in self._tx_lst:
            if not tx.CheckTransaction():
                print("CheckBlock() : CheckTransaction failed")
                return False

        return True

    # def hash_transactions(self):
    #     # return a hash of the transactions in the block
    #     tx_hashs = []

    #     for tx in self._tx_lst:
    #         tx_hashs.append(tx.ID)

    #     return utils.sum256_hex(utils.encode(''.join(tx_hashs)))

    def serialize(self):
        # serializes the block
        return pickle.dumps(self)

    def deserialize(self, data):
        """
        Deserializes the block.
        :param `bytes` data: The serialized data.
        :return: A Block object.
        :rtype: Block object.
        """
        return pickle.loads(data)


