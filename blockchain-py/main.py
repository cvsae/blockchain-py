from block import *

from wallet import Wallet
from wallets import Wallets 

from transaction import Transaction
from transaction import UTXOTx
from transaction import CoinbaseTx
from transaction_input import TXInput
from transaction_output import TXOutput
from utxo_set import UTXOSet

from blockchain import Blockchain

from datetime import datetime
from functools import partial

import context as ctx
import utils
import version


from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint
from twisted.internet.endpoints import connectProtocol
from twisted.internet.task import LoopingCall
from twisted.internet.error import CannotListenError


from tkinter import *
from tkinter import messagebox
import _thread



PING_INTERVAL = 1200.0 # 20 min = 1200.0
SYNC_INTERVAL = 15  # 15 seconds


COIN = 100000000
bnProofOfWorkLimit = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

class Error(Exception):
    pass


def _print(*args):
    time = datetime.now().time().isoformat()[:8]
    print (" ".join(map(str, args)))



def GetNextWorkRequired(pindexLast):

    if pindexLast == None:
        return 10
    
    # Difficulty will change every 600 seconds or 10 minuntes
    nTargetTimespan = 600 
    # We need a new block every 100 seconds
    nTargetSpacing = 50
    # That give us a interval 12 blocks
    nInterval = nTargetTimespan / nTargetSpacing

    # Only change once per interval
    if ((ctx.mapBlockHeight[pindexLast]+1) % nInterval != 0):
        return ctx.mapBlockIndex[pindexLast].bits


    # A dictionary that allow to access a block hash by height 
    heights = dict((v,k) for k,v in ctx.mapBlockHeight.items())



    
    nActualTimespan = int(ctx.mapBlockIndex[pindexLast].timestamp - ctx.mapBlockIndex[heights[ctx.mapBlockHeight[pindexLast] - nInterval + 2]].timestamp)
   
    
    if nActualTimespan < nTargetTimespan/4:
        nActualTimespan = nTargetTimespan/4
    if nActualTimespan > nTargetTimespan*4:
        nActualTimespan = nTargetTimespan*4



    bnNew = utils.bits2target(ctx.mapBlockIndex[pindexLast].bits)
    bnNew *= nActualTimespan
    bnNew /= nTargetTimespan

    if bnNew > bnProofOfWorkLimit:
        bnNew = bnProofOfWorkLimit

    utils.logg("\n\n\nGetNextWorkRequired RETARGET *****\n")
    utils.logg("nTargetTimespan = %d    nActualTimespan = %d\n" %(nTargetTimespan, nActualTimespan,))
    utils.logg("Last %d blocks time average was %d\n" %(nInterval, nActualTimespan,))
    utils.logg("Before: %08x  %s\n" %(ctx.mapBlockIndex[pindexLast].bits, nActualTimespan,))
    utils.logg("After:  %08x  %s\n" %(utils.GetCompact(int(bnNew)), nActualTimespan,))


    return utils.target2bits(bnNew)




def AddAddress(address, wallet):
    # Add address to wallet 
    wallets = Wallets()
    wallets.add_wallet(address, wallet)
    return wallets.save_to_file()



def GenerateNewAddress():
    # Generate an address, return the address only if is added to wallet 
    wallet = Wallet()
    address = wallet.address
    if not AddAddress(address, wallet):
        raise Error("GenerateNewAddress() : AddAddress failed\n")
    return address


def isMineAddress(address):
    # check if address is in our wallet 
    wallets = Wallets()
    return address in wallets.get_addresses()


def get_address_balance(address):
    # get address balance for a specifiedc address
    bc = Blockchain()
    utxo_set = UTXOSet(bc)

    pubkey_hash = utils.address_to_pubkey_hash(address)
    utxos = utxo_set.find_utxo(pubkey_hash)
    balance = 0

    for out in utxos:
        balance += out.value

    return balance / COIN



def listAddresses():
    # return a list of wallet addresses
    wallets = Wallets()
    return wallets.get_addresses()




def get_balance():
    all_ = listAddresses()

    val = 0 
    for addr in all_:
        val += get_address_balance(addr)

    return str(val) 





def next_block(block_hash):
    # return the next block hash of the given block hash 
    dict_keys = list(CTX.mapBlockIndex.keys())
    try:
        return dict_keys[dict_keys.index(block_hash) + 1]
    except IndexError:
        return -1



def calculate_difficulty():
    # return difficulty
    p = utils.bits2target(0x1d00ffff)
    y = utils.bits2target(ctx.mapBlockIndex[ctx.bestBlockHash].bits)
    return float(p) / float(y)





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

    utils.logg('Loading BlockIndex')

    #
    # Load block index
    #

    for block in reversed(list(blockchain.blocks)):
        # add to index 
        ctx.mapBlockIndex[block.hash] = block 
        ctx.BestHeight = ctx.BestHeight + 1
        ctx.bestBlockHash = block.hash
        ctx.mapBlockHeight[block.hash] = ctx.BestHeight


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
        
        

        

        # Block 

        block = Block([txnew])
        block.prev_block_hash = ''
        block.timestamp = 1607965519
        block.bits = 0x1e0fffff
        block.nonce = 1484712


        #Block(timestamp=b'1607965519', tx_lst=[Transaction(id='12c86ae42baf87e9186cd2fabae575e5534ee0bb82a61a8d0d5616d3ec9bf029', 
        #vin=[TXInput(tx_id=b'', vout=-1, signature=None, public_key='The Times 03/Jan/2009 Chancellor on brink of second bailout for banks')],
        #vout=[TXOutput(address='1F6kc25HfrXcn9b4brsNzCiTDWuqsDzAmx', value=5000000000, public_key_hash='9aa83d479c33c697cd727fc87d753d2d7f2daf19')])], 
        #prev_block_hash=b'', hash=None, nonce=1484712, bits=504365055)


        assert(block.getHash() == '0000054bd29593ff231e77f7005a9e288e162bbda8cb8962077d57d9be8f87c0')
        

        blockchain._block_put(block)
        utxo_set = UTXOSet(blockchain)
        utxo_set.reindex()
                        
        utils.logg('Genesis block added to database')
                        
        # add to index 
        ctx.mapBlockIndex[block.hash] = block 
        ctx.mapBlockHeight[block.hash] = 1
        ctx.BestHeight = ctx.BestHeight + 1
        ctx.bestBlockHash = block.hash

        # Miner
        
        '''
        target = utils.bits2target(block.bits)

        i = 0 
        while 1:
            block.nonce = i 
            hash_hex = block.getHash()
            hash_int = int(hash_hex, 16)
            if hash_int < target:
                print (hash_hex, block.nonce, block.timestamp)

            i +=1

        '''
        
    return True


def AcceptBlock(block):
   

    bc = Blockchain()
    if bc.haveBlock(block.hash):
        utils.logg('ProccessBlock() Error - Block %s already exists' %block.hash)
        return False 

    # Check prev block
    if bc._tip != block.prev_block_hash:
        utils.logg("Proccess().thisBlock : prev block not found")
        return False


    # Check timestamp against prev
    if bc.getBlock(bc._tip).timestamp >= block.timestamp:
        utils.logg("Proccess().thisBlock : block's timestamp is too early")
        return False

    #  Check Proof Of Work
    if block.bits != GetNextWorkRequired(ctx.bestBlockHash):
        utils.logg("Proccess().thisBlock : incorrect proof of work")
        return False

    if not bc._block_put(block):
        utils.logg("AcceptBlock() : WriteToDisk failed")
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
        utils.logg('ProccessBlock() Error - Block %s already exists' %blockhash)
        return False 


    if not block.CheckBlock():
        utils.logg("ProcessBlock() : CheckBlock FAILED")
        return True


    if not ctx.mapBlockIndex[block.prev_block_hash]:
        utils.logg("ProcessBlock: ORPHAN BLOCK, prev=%s\n" %block.prev_block_hash)

    if not AcceptBlock(block):
        utils.logg("ProcessBlock() : AcceptBlock FAILED")
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

    utils.logg('Running Miner with %d txs in block' %len(block._tx_lst))


    block.timestamp = int(time.time())
    block.prev_block_hash = ctx.bestBlockHash
    block.nonce = 0 
    block.bits = GetNextWorkRequired(ctx.bestBlockHash) # 

   

    
    # target
    target = utils.bits2target(block.bits)

    i = 0 

    while 1:
        block.nonce = i 
        hash_hex = block.getHash()
        hash_int = int(hash_hex, 16)
        if hash_int < target:
            # proccess this block
            utils.logg('Miner found a block %s' %hash_hex)
            if ProccessBlock(block, block.nonce):
                utils.logg('Miner block accepted:')                
                return True
            else:
                utils.logg('Miner block rejected:') 
                return False
            break

        i +=1


if loadBlockIndex():
    utils.logg('BlockIndex loaded')

    
def Mining():
    while 1:
        f = Miner([])





############################################################################################


class NCProtocol(Protocol):
    def __init__(self, factory, state="GETHELLO", kind="LISTENER"):
        self.factory = factory
        self.state = state
        self.VERSION = 0
        self.ProtocolVersion = version._protocol_version
        self.remote_nodeid = None
        self.remote_node_protocol_version = None
        self.kind = kind
        self.nodeid = self.factory.nodeid



        self.lc_ping = LoopingCall(self.send_PING)
        self.lc_sync = LoopingCall(self.send_SYNC)
        self.message = partial(utils.envelope_decorator, self.nodeid)
        
        self.factory.status = "Running"

    def connectionMade(self):
        r_ip = self.transport.getPeer()
        h_ip = self.transport.getHost()
        self.remote_ip = r_ip.host + ":" + str(r_ip.port)
        self.host_ip = h_ip.host + ":" + str(h_ip.port)

    def print_peers(self):
        if len(self.factory.peers) == 0:
            utils.logg(" [!] PEERS: No peers connected.")
        else:
            utils.logg(" [ ] PEERS:")
            for peer in self.factory.peers:
                addr, kind = self.factory.peers[peer][:2]
                utils.logg(" [*] %s at %s %s " %(peer, addr, kind))

    def write(self, line):
        self.transport.write(line + "\n")

    def connectionLost(self, reason):
        # NOTE: It looks like the NCProtocol instance will linger in memory
        # since ping keeps going if we don't .stop() it.
        try: self.lc_ping.stop()
        except AssertionError: pass

        try:
            self.factory.peers.pop(self.remote_nodeid)
            if self.nodeid != self.remote_nodeid:
                self.print_peers()
        except KeyError:
            if self.nodeid != self.remote_nodeid:
                _print(" [ ] GHOST LEAVES: from", self.remote_nodeid, self.remote_ip)

    def dataReceived(self, data):
        for line in data.splitlines():
            line = line.strip()
            envelope = utils.read_envelope(line)
            if self.state in ["GETHELLO", "SENTHELLO"]:
                # Force first message to be HELLO or crash
                if envelope['msgtype'] == 'hello':
                    self.handle_HELLO(line)
                else:
                    utils.logg(f" [!] Ignoring {envelope['msgtype']}  in {self.state}")
            else:
                if envelope['msgtype'] == 'ping':
                    self.handle_PING(line)
                elif envelope['msgtype'] == 'pong':
                    self.handle_PONG(line)
                elif envelope['msgtype'] == 'addr':
                    pass
                elif envelope['msgtype'] == 'sync':
                    self.handle_SYNC(line)
                elif envelope['msgtype'] == 'givemeblocks':
                    self.handle_SENDBLOCKS(line)
                elif envelope['msgtype'] == 'getblock':
                    self.handleRECEIVEDBLOCK(line)


    def send_PING(self):
        # Send a pig message to remote peer 
        utils.logg(" [>] PING   to %s %s" %(self.remote_nodeid, self.remote_ip))
        # Build a ping message
        ping = utils.create_ping(self.nodeid)
        # send the ping message
        self.write(ping)



    def handle_PING(self, ping):
        # Receive a ping message 
        if utils.read_message(ping):
            # Build a pong message
            pong = utils.create_pong(self.nodeid)
            # send the pong message
            self.write(pong)


    def handle_PONG(self, pong):
        # Receive a pong message 
        pong = utils.read_message(pong)
        # loggig
        utils.logg("[<] PONG from %s at %s" %(self.remote_nodeid, self.remote_ip))
        # hacky
        addr, kind = self.factory.peers[self.remote_nodeid][:2]
        self.factory.peers[self.remote_nodeid] = (addr, kind, time())



    def send_SYNC(self):
        # Send a sync message to remote peer 
        utils.logg("[>] Asking %s if we need sync" %self.remote_nodeid)
        # Build a sync message, contains our best height and our besthash
        sync = utils.create_sync(self.nodeid, ctx.BestHeight, ctx.bestBlockHash)
        # send the sync message
        self.write(sync)



    def handle_SYNC(self, line):
        # Got a reply about a sync message
        utils.logg("[>] Got reply about sync message from %s" %self.remote_nodeid)
        # read sync message
        data = utils.read_message(line)
        # peer height 
        peerHeight = data["bestheight"]


        # we have missing blocks, we are behind
        if peerHeight > ctx.BestHeight:
            # calculate the diffrence 
            diffrence = peerHeight - ctx.BestHeight
            # logging
            utils.logg("We need sync, we are behind %d blocks" %diffrence)
            # set dialog 
            self.factory.dialog = "Need sync"
            # build a ask blocks message 
            message = utils.create_ask_blocks(self.nodeid, ctx.bestBlockHash)
            # send ask block message to peer 
            self.write(message)

        # peer heigfht == our heigh okkk  
        elif peerHeight == ctx.BestHeight:
            self.factory.dialog = "Synced"
            utils.logg("we are synced")



    def handle_SENDBLOCKS(self, line):
        # A peer ask us top send him blocks 
        utils.logg("[>] Got sendblocks message from %s" %self.remote_nodeid)

        # read peer message 
        data = utils.read_message(line)
        # extract remote peer besthash from message
        peer_best = data["besthash"]


        # be sure that we have peer besthash block  
        if peer_best in ctx.mapBlockIndex:
            # find the next block hash
            next_hash = next_block(peer_best)
            # access the block object of the next hash 
            block = ctx.mapBlockIndex[next_hash]
            # serialize the block object
            ret = block.serialize()
            # build a sent block message containing serialized block 
            message = utils.create_send_block(self.nodeid, ret)
            # send the block to peer 
            self.write(message)
            # logg :P
            utils.logg("block %s send to %s" %(thisHeight +1, self.remote_nodeid))
        else:
            pass



    def handleRECEIVEDBLOCK(self, line):
        # We rceive a new block 
        utils.logg("Proccesing block from %s" %(ctx.getBestHeight +1, self.remote_nodeid))
        # read block message
        data = utils.read_message(line)
        # extract block from message 
        block = data["block"]
        

        # check if rceived block* is an instance of the Block object
        if isinstance(block, Block):
            # deserialize the blockk 
            pblock = Block([]).deserialize(block)
            # procces this block 
            if ProccessBlock(block, block.nonce):
                utils.logg('Miner block accepted:')                
            else:
                utils.logg('Miner block rejected:')
        else:
            pass


    def send_ADDR(self):
        utils.logg(" [>] Telling to %s about my peers" %self.remote_nodeid)
        # Shouldn't this be a list and not a dict?
        peers = self.factory.peers
        listeners = [(n, peers[n][0], peers[n][1], peers[n][2])
                     for n in peers]
        addr = utils.create_addr(self.nodeid, listeners)
        self.write(addr)



    def handle_ADDR(self, addr):
        try:
            nodes = utils.read_message(addr)['nodes']
            utils.logg(" [<] Recieved addr list from peer %s" %self.remote_nodeid)
            #for node in filter(lambda n: nodes[n][1] == "SEND", nodes):
            for node in nodes:
                utils.logg(" [*] %s %s" %(node[0], node[1]))

                if node[0] == self.nodeid:
                    utils.logg("[!] Not connecting to %s thats me!" %node[0])
                    return
                if node[1] != "SPEAKER":
                    utils.logg("[!] Not connecting to %s is %s" %(node[0], node[1]))
                    return
                if node[0] in self.factory.peers:
                    utils.logg("[!] Not connecting to %s already connected" %node[0])
                    return
                _print(" [ ] Trying to connect to peer " + node[0] + " " + node[1])
                # TODO: Use [2] and a time limit to not connect to "old" peers
                host, port = node[0].split(":")
                point = TCP4ClientEndpoint(reactor, host, int(port))
                d = connectProtocol(point, NCProtocol(ncfactory, "SENDHELLO", "SPEAKER"))
                d.addCallback(gotProtocol)
        except utils.InvalidSignatureError:
            _print(" [!] ERROR: Invalid addr sign ", self.remote_ip)
            self.transport.loseConnection()



    



    def send_HELLO(self):
        hello = utils.create_hello(self.nodeid, self.VERSION, self.ProtocolVersion)
        #_print(" [ ] SEND_HELLO:", self.nodeid, "to", self.remote_ip)
        self.transport.write(hello + "\n")
        self.state = "SENTHELLO"



    def handle_HELLO(self, hello):
        try:
            hello = utils.read_message(hello)
            self.remote_nodeid = hello['nodeid']
            self.remote_node_protocol_version = hello["protocol"]


            if self.remote_nodeid == self.nodeid:
                utils.logg("[!] Found myself at %s" %self.host_ip)
                self.transport.loseConnection()
            else:
                if self.state == "GETHELLO":
                    my_hello = utils.create_hello(self.nodeid, self.VERSION, self.ProtocolVersion)
                    self.transport.write(my_hello + "\n")
                self.add_peer()
                self.state = "READY"
                self.print_peers()
                #self.write(utils.create_ping(self.nodeid))
                if self.kind == "LISTENER":
                    # The listener pings it's audience
                    utils.logg("[ ] Starting pinger to %s" %self.remote_ip)
                    self.lc_ping.start(PING_INTERVAL, now=False)
                    # Tell new audience about my peers
                    self.send_ADDR()
                self.lc_sync.start(SYNC_INTERVAL, now=True)
        except utils.InvalidSignatureError:
            _print(" [!] ERROR: Invalid hello sign ", self.remote_ip)
            self.transport.loseConnection()



    def add_peer(self):
        entry = (self.remote_ip, self.kind, self.remote_node_protocol_version, time())
        self.factory.peers[self.remote_nodeid] = entry
        utils.logg("[] peer %s at %s with protocol version %d added to peers list" %(self.remote_nodeid, self.remote_ip, self.remote_node_protocol_version))



# Splitinto NCRecvFactory and NCSendFactory (also reconsider the names...:/)
class NCFactory(Factory):
    def __init__(self):
        self.peers = {}
        self.numProtocols = 0
        self.nodeid = utils.generate_nodeid()[:10]
        self.status = None
        self.dialog = "n/a"

    def startFactory(self):
        utils.logg("Node started")

    def stopFactory(self):
        reactor.callFromThread(reactor.stop)

    def buildProtocol(self, addr):
        return NCProtocol(self, "GETHELLO", "LISTENER")

def gotProtocol(p):
    # ClientFactory instead?
    p.send_HELLO()
    
    
def Start(factory):

    
    
    p2p_host = utils.p2p_host
    p2p_port = utils.p2p_port
        
    try:
        endpoint = TCP4ServerEndpoint(reactor, int(p2p_port), interface=p2p_host)
        utils.logg(" [ ] LISTEN: at %s:%d" %(p2p_host, (int(p2p_port))))
        endpoint.listen(factory)
    except CannotListenError:
        utils.logg("[!] Address in use")
        raise SystemExit


    # connect to bootstrap addresses
    utils.logg(" [ ] Trying to connect to bootstrap hosts:")
    
    #point = TCP4ClientEndpoint(reactor, p2p_port, int(p2p_port))
    #d = connectProtocol(point, NCProtocol(factory, "SENDHELLO", "LISTENER"))
    #d.addCallback(gotProtocol)
    
    reactor.run(installSignalHandlers=0)




###################################################################################








class Client:

    def __init__(self, root):
        self.root = root
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.frame = Frame(self.root)
        self.frame.pack()

    
        
        # store wallet balance
        self.balance_ = StringVar()
        # store address
        self.addr_ = StringVar()
        # store blockchain info 
        self.block_chain_ = StringVar()
        # store ming op info
        self.startorstopmining_ = StringVar()
        # mining ?.?
        self._runMiner = False
        # info
        self.ninfo_ = StringVar()


        # hacky
        self.factory = NCFactory()


        # start networking 
        _thread.start_new_thread(Start, ((self.factory,)))
        # start local info_n
        _thread.start_new_thread(self._update, ())
        

        # show address dialog
        self.addr()
        # show balance dialog 
        self.balance()
        # show send dialog 
        self.send()
        # show blockchain info dialog 
        self.blockchain()
        # show mining info dialog 
        self.mining()
        # show networkinf dialog 
        self.networking()



    def blockchaininfo(self):
        return "Height: %d | Difficulty: %f | Best hash: %s.." %(ctx.BestHeight, calculate_difficulty(), ctx.bestBlockHash[:15])

    
    def networkinginfo(self):
            return "Status: %s | Dialog: %s | Connected Peers: %d" %(self.factory.status, self.factory.dialog, len(self.factory.peers))


    def _update(self):
        # generate an address
        addr = GenerateNewAddress()

        while True:
            self.balance_.set(get_balance())
            self.addr_.set(addr)
            self.block_chain_.set(self.blockchaininfo())
            self.startorstopmining_.set(self.sosm())
            self.ninfo_.set(self.networkinginfo())



    def addr(self):
        addr_f = LabelFrame(self.frame, text="Received Address", padx=5, pady=5)
        addr_f.grid(sticky=E+W)
        Entry(self.frame, state="readonly", textvariable=self.addr_, width=80).grid(in_=addr_f)



    def balance(self):
        addr_balance = LabelFrame(self.frame, text="Balance", padx=5, pady=5)
        addr_balance.grid(sticky=E+W)
        Entry(self.frame, state="readonly", textvariable=self.balance_, width=50).grid(in_=addr_balance)


    def blockchain(self):
        blockchain_info = LabelFrame(self.frame, text="Blockchain Info", padx=5, pady=5)
        blockchain_info.grid(sticky=E+W)
        Entry(self.frame, state="readonly", textvariable=self.block_chain_, width=90).grid(in_=blockchain_info)


    def send(self):
        send_f = LabelFrame(self.frame, text="Send Coin", padx=5, pady=15)
        send_f.grid(sticky=E+W)
        to_l = Label(self.frame, text="To: ").grid(in_=send_f)
        self.to = Entry(self.frame)
        self.to.grid(in_=send_f, row=0, column=1, sticky=W)
        amount_l = Label(self.frame, text="Amount: ").grid(in_=send_f, row=0, column=3, sticky=W)
        self.amount = Entry(self.frame, width=4)
        self.amount.grid(in_=send_f, row=0, column=4, sticky=W)
        Label(self.frame, text="   ").grid(in_=send_f, row=0, column=5)
        Label(self.frame, text="   ").grid(in_=send_f, row=0, column=2)
        send_b = Button(self.frame, command=self._send, text="Send").grid(in_=send_f, row=0, column=8, sticky=W+E)


    def _send(self):
        amount = self.amount.get()
        recipt = self.to.get()
        # not implemented

    def mining(self):
        mining_f = LabelFrame(self.frame, text="Mining", padx=3, pady=5)
        mining_f.grid(sticky=E+W)
        send_b = Button(self.frame, command=self.__mining, textvariable=self.startorstopmining_).grid(in_=mining_f, row=0, column=4, sticky=W+E)


    def networking(self):
        networking_info = LabelFrame(self.frame, text="Network Info", padx=5, pady=5)
        networking_info.grid(sticky=E+W)
        Entry(self.frame, state="readonly", textvariable=self.ninfo_, width=50).grid(in_=networking_info)


    def __mining(self):
        if self.startorstopmining_.get() == "Start":
            #_thread.start_new_thread(Miner([]), ())
            _thread.start_new_thread(Mining, ())
            messagebox.showinfo("Mining...", "CoinMiner Started.")
            self._runMiner = True
        else:
            messagebox.showinfo("Mining...", "CoinMiner Stoped.")
            self._runMiner = False


    def sosm(self):
        if self._runMiner:
           return "Stop"        
        return 'Start'


    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            # stop factory before close 
            self.factory.stopFactory()
            root.destroy()






root = Tk()
root.geometry("655x330+350+100")
Client(root=root)
root.title("MyCoin")
root.mainloop()
