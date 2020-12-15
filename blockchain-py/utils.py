import hashlib
import binascii
import unittest
import pickle
import json
import hmac
import time
import logging
import struct 
import os

import ecdsa

import base58


nSubsibyHalvingInterval = 100
strSetDataDir = False


p2p_host = '127.0.0.1'
p2p_port = '9191'

def GetAppDir():
    strDir = ''
    if strSetDataDir:
        strDir = strSetDataDir        

    elif os.getenv("APPDATA"):
         strDir = "%s\\lela" %os.getenv("APPDATA")
    elif of.getenv("USERPROFILE"):
        strAppData = "%s\\Application Data" %os.getenv("USERPROFILE")
        fMkdirDone = False 
        if not fMkdirDone:
            fMkdirDone = True
            os.mkdir(strAppData)
        strDir = "%s\\lela" %strAppData
    else:
        return "."

    if not os.path.exists(strDir):
        os.mkdir(strDir)

    return strDir



def logg(msg):
    logging.basicConfig(level=logging.INFO, filename= GetAppDir() + str(r'\debug.log'), format='%(asctime)s %(message)s') # include timestamp
    logging.info(msg)


def bits2target(bits):
    """ Convert bits to target """
    exponent = ((bits >> 24) & 0xff)
    mantissa = bits & 0x7fffff
    if (bits & 0x800000) > 0:
        mantissa *= -1 
    return (mantissa * (256**(exponent-3)))


def target2bits(target):
        MM = 256*256*256
        c = ("%064X"%int(target))[2:]
        i = 31
        while c[0:2]=="00":
            c = c[2:]
            i -= 1
        c = int('0x'+c[0:6],16)
        if c >= 0x800000:
            c //= 256
            i += 1
        new_bits = c + MM * i
        return new_bits

def num2mpi(n):
        """convert number to MPI string"""
        if n == 0:
                return struct.pack(">I", 0)
        r = r""
        neg_flag = bool(n < 0)
        n = abs(n)
        while n:
                r = chr(n & 0xFF) + r
                n >>= 8
        if ord(r[0]) & 0x80:
                r = chr(0) + r
        if neg_flag:
                r = chr(ord(r[0]) | 0x80) + r[1:]
        datasize = len(r)
        return struct.pack(">I", datasize) + encode(r)



def GetCompact(n):
    """convert number to bc compact uint"""
    mpi = num2mpi(n)
    nSize = len(mpi) - 4
    nCompact = (nSize & 0xFF) << 24
    if nSize >= 1:
        nCompact |= (mpi[4] << 16)
    if nSize >= 2:
        nCompact |= (mpi[5] << 8)
    if nSize >= 3:
        nCompact |= (mpi[6] << 0)
    return nCompact


def serialize(data):
    return pickle.dumps(data)


def deserialize(data):
    return pickle.loads(data)


def hash_public_key(pubkey):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(binascii.unhexlify(pubkey)).digest())
    return ripemd160.hexdigest()


def get_address(pubkey_hash):
    return base58.base58CheckEncode(0x00, pubkey_hash)


def address_to_pubkey_hash(address):
    # return base58.b58decode_check(encode(address))[1:]
    return base58.base58CheckDecode(address)


def privatekey_to_wif(key):
    return base58.base58CheckEncode(0x80, key)


def privatekey_to_publickey(key):
    sk = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return '04' + decode(binascii.hexlify(vk.to_string()))


def encode(str, code='utf-8'):
    return str.encode(code)


def decode(bytes, code='utf-8'):
    return bytes.decode(code)


def pubkey_to_verifykey(pub_key, curve=ecdsa.SECP256k1):
    vk_string = binascii.unhexlify(encode(pub_key[2:]))
    return ecdsa.VerifyingKey.from_string(vk_string, curve=curve)


def sum256_hex(*args):
    m = hashlib.sha256()
    for arg in args:
        m.update(arg)
    return m.hexdigest()


def sum256_byte(*args):
    m = hashlib.sha256()
    for arg in args:
        m.update(arg)
    return m.digest()


def GetBlockValue(height, fees):
    subsidy = nCoin * COIN
    subsidy >>= (height / nSubsibyHalvingInterval)
    return subsidy + fees



class ContinueIt(Exception):
    pass


class BreakIt(Exception):
    pass






def generate_nodeid():
    return hashlib.sha256(os.urandom(2568)).hexdigest()


nonce = lambda:generate_nodeid()

##### MESSAGES 

def decode_dict(d):
    result = {}
    for key, value in d.items():
        if isinstance(key, bytes):
            key = key.decode()
        if isinstance(value, bytes):
            value = value.decode()
        elif isinstance(value, dict):
            value = decode_dict(value)
        result.update({key: value})
    return result



def encode_dict(d):
    result = {}
    for key, value in d.items():
        if isinstance(key, str):
            key = key.encode()
        if isinstance(value, str):
            value = value.encode()
        elif isinstance(value, dict):
            value = decode_dict(value)
        result.update({key: value})
    return result



def make_envelope(msgtype, msg, nodeid):
    msg['nodeid'] = nodeid
    msg['nonce'] =  nonce()
    data = json.dumps(msg)
    sign =  hmac.new(key=nodeid.encode('utf-8'), msg=data.encode('utf-8'), digestmod=hashlib.sha256)


    envelope = {'data': msg,
                'sign': sign.hexdigest(),
                'msgtype': msgtype}
    return json.dumps(decode_dict(envelope))

def envelope_decorator(nodeid, func):
    msgtype = func.__name__.split("_")[0]
    def inner(*args, **kwargs):
        return make_envelope(msgtype, func(*args, **kwargs), nodeid)
    return inner




# ------

def create_ackhello(nodeid):
    msg = {}
    return make_envelope(b"ackhello", msg, nodeid)


def create_hello(nodeid, version, protoversion):
    msg = {'version': version, 'protocol': protoversion}
    return make_envelope("hello", msg, nodeid)


def create_send_block(nodeid, block):
    msg = {'block': block}
    return make_envelope("getblock", msg, nodeid)



def create_ask_blocks(nodeid, besthash):
    msg = {'besthash': besthash}
    return make_envelope("givemeblocks", msg, nodeid)


def read_envelope(message):
    return json.loads(message)

def read_message(message):
    """Read and parse the message into json. Validate the signature
    and return envelope['data']
    """
    envelope = json.loads(message)
    nodeid = str(envelope['data']['nodeid'])
    signature = str(envelope['sign'])
    msg = json.dumps(envelope['data'])
    verify_sign = hmac.new(key=nodeid.encode('utf-8'), msg=msg.encode('utf-8'), digestmod=hashlib.sha256)
    return envelope['data']
