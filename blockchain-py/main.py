from wallet import Wallet
from wallets import Wallets 
from transaction import Transaction
from transaction import UTXOTx
from transaction import CoinbaseTx
from transaction_input import TXInput
from transaction_output import TXOutput
from block import Block
from blockchain import Blockchain
import context as ctx
from utxo_set import UTXOSet
import utils
from block import *

COIN = 100000000

class Error(Exception):
    pass


def AddAddress(address, wallet):
    wallets = Wallets()
    wallets.add_wallet(address, wallet)
    return wallets.save_to_file()



def GenerateNewAddress():
    wallet = Wallet()
    address = wallet.address
    if not AddAddress(address, wallet):
        raise Error("GenerateNewAddress() : AddAddress failed\n")
    return address


def isMineAddress(address):
    wallets = Wallets()
    return address in wallets.get_addresses()


def get_address_balance(address):
    bc = Blockchain()
    utxo_set = UTXOSet(bc)

    pubkey_hash = utils.address_to_pubkey_hash(address)
    utxos = utxo_set.find_utxo(pubkey_hash)
    balance = 0

    for out in utxos:
        balance += out.value

    return balance / COIN



def listAddresses():
    wallets = Wallets()
    return wallets.get_addresses()




def get_balance():
    all_ = listAddresses()

    val = 0 
    for addr in all_:
        val += get_address_balance(addr)

    return str(val) 




def send(from_addr, to_addr, amount):
    bc = Blockchain()
    utxo_set = UTXOSet(bc)
    tx = UTXOTx(from_addr, to_addr, amount, utxo_set)


    inputs = []
    outputs = []

    for vin in tx.vin:
        ctxin = TXInput()
        ctxin._tx_id = vin.tx_id
        ctxin._vin = vin.vout 
        ctxin._sig = vin.signature 
        ctxin._public_key = vin.public_key 

        inputs.append(ctxin)

    for vout in tx.vout:
        outputs.append(TXOutput(vout.value, vout.address))

    txnew = Transaction()
    txnew._id = tx.ID
    txnew._vin = inputs
    txnew._vout = outputs

    return txnew


def loadBlockIndex():
    blockchain = Blockchain()

    #
    # Load block index
    #

    for block in reversed(list(blockchain.blocks)):
        # add to index 
        ctx.mapBlockIndex[block.hash] = block 
        ctx.mapBlockHeight[block.hash] = 1
        ctx.BestHeight = ctx.BestHeight + 1
        ctx.bestBlockHash = block.hash


    #
    # Init with genesis block
    #

    if len(ctx.mapBlockIndex) == 0:
        txnew = Transaction()

        # Transaction

        # inputs 
        txnew.vin[0].tx_id = ''
        txnew.vin[0].vout = -1
        txnew.vin[0].public_key = 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'
        # output
        txnew.vout[0].value = 50 * COIN
        txnew.vout[0].address = '1F6kc25HfrXcn9b4brsNzCiTDWuqsDzAmx'
        txnew.set_id()
        
        # Transaction(id='12c86ae42baf87e9186cd2fabae575e5534ee0bb82a61a8d0d5616d3ec9bf029', 
        # vin=[TXInput(tx_id=b'', vout=-1, signature=None, public_key='The Times 03/Jan/2009 Chancellor on brink of second bailout for banks')], 
        # vout=[TXOutput(address='1F6kc25HfrXcn9b4brsNzCiTDWuqsDzAmx', value=5000000000, public_key_hash='9aa83d479c33c697cd727fc87d753d2d7f2daf19')])
        
        

        target = 1 << (256 - 9)

        # Block 

        block = Block([txnew])
        block.prev_block_hash = ''
        block.timestamp = 1607733691
        block.nonce = 1044

        # Block(timestamp=b'1607733691', tx_lst=[Transaction(id='12c86ae42baf87e9186cd2fabae575e5534ee0bb82a61a8d0d5616d3ec9bf029', vin=[TXInput(tx_id=b'', 
        # vout=-1, signature=None, public_key='The Times 03/Jan/2009 Chancellor on brink of second bailout for banks')], 
        # vout=[TXOutput(address='1F6kc25HfrXcn9b4brsNzCiTDWuqsDzAmx', value=5000000000, public_key_hash='9aa83d479c33c697cd727fc87d753d2d7f2daf19')])], 
        # prev_block_hash=b'', hash=b'00549c610a4c2b0fd6684f482100c90e6f6ca89786bb4d16232f402584776b39', nonce=1044)


        assert(block.getHash() == '00549c610a4c2b0fd6684f482100c90e6f6ca89786bb4d16232f402584776b39')

        blockchain._block_put(block)
        utxo_set = UTXOSet(blockchain)
        utxo_set.reindex()

        print('genesis added\n')

        # add to index 
        ctx.mapBlockIndex[block.hash] = block 
        ctx.mapBlockHeight[block.hash] = 1
        ctx.BestHeight = ctx.BestHeight + 1
        ctx.bestBlockHash = block.hash



        # Miner
        
        '''
        i = 0 
        while 1:
            block.nonce = i 
            hash_hex = block.getHash()
            hash_int = int(hash_hex, 16)
            if hash_int < target:
                print (hash_hex, block.nonce)

            i +=1
        '''
    return True


def AcceptBlock(block):
   

    bc = Blockchain()
    if bc.haveBlock(block.hash):
        print('ProccessBlock() Error - Block %s already exists' %block.hash)
        return False 

    # Check prev block
    if bc._tip != block.prev_block_hash:
        print("Proccess().thisBlock : prev block not found")
        return False


    # Check timestamp against prev
    if bc.getBlock(bc._tip).timestamp >= block.timestamp:
        print("Proccess().thisBlock : block's timestamp is too early")
        return False

    #  Check Proof Of Work
    if block.bits != 16:
        print("Proccess().thisBlock : incorrect proof of work")
        return False

    if not bc._block_put(block):
        print("AcceptBlock() : WriteToDisk failed")
        return False


    utxo_set = UTXOSet(bc)
    utxo_set.reindex()
        
    ctx.mapBlockIndex[block.hash] = block 
    ctx.BestHeight = ctx.BestHeight + 1
    ctx.mapBlockHeight[block.hash] = ctx.BestHeight
    ctx.bestBlockHash = block.hash
    

    return True


def ProccessBlock(block, nonce):
    blockhash = block.getHash()


    # Check for duplicate
    bc = Blockchain()
    if bc.haveBlock(blockhash):
        print('ProccessBlock() Error - Block %s already exists' %blockhash)
        return False 


    if not block.CheckBlock():
        print("ProcessBlock() : CheckBlock FAILED")
        return True


    if not ctx.mapBlockIndex[block.prev_block_hash]:
        print("ProcessBlock: ORPHAN BLOCK, prev=%s\n" %block.prev_block_hash)

    if not AcceptBlock(block):
        print("ProcessBlock() : AcceptBlock FAILED")
        return False

    

    return True



def Miner(txs):
    address = GenerateNewAddress()

    # create a coinbase transaction
    txnew = Transaction()
    txnew.vin[0].tx_id = ''
    txnew.vin[0].public_key = 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'
    txnew.vout[0].value = 50 * COIN
    txnew.vout[0].address = address
    txnew.set_id()

    # create new block and Add our coinbase tx as first transaction
    block = Block([txnew])

    # Collect the latest transactions into the block
    if len(txs) > 0:
        for tx in txs:
            block._tx_lst.append(tx)

    print('Running Miner with %d txs in block' %len(block._tx_lst))


    block.timestamp = int(time.time())
    block.prev_block_hash = ctx.bestBlockHash
    block.nonce = 0 
    block.bits = 16


    
    # target
    target = 1 << (256 - block.bits)

    i = 0 

    while 1:
        block.nonce = i 
        hash_hex = block.getHash()
        hash_int = int(hash_hex, 16)
        if hash_int < target:
            # proccess this block
            if ProccessBlock(block, block.nonce):
                print('Block found')
                return True
            
            break

        i +=1


loadBlockIndex()

    
def Mining():
    while 1:
        f = Miner([])
