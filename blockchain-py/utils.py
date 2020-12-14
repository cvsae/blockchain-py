import hashlib
import binascii
import unittest
import pickle
import os

import ecdsa

import base58


nSubsibyHalvingInterval = 100
strSetDataDir = False

def GetAppDir():
    strDir = ''
    if strSetDataDir:
        strDir = strSetDataDir
    elif os.getenv("APPDATA"):
         strDir = "%s\\mycoinsss" %os.getenv("APPDATA")
    elif of.getenv("USERPROFILE"):
        strAppData = "%s\\Application Data" %os.getenv("USERPROFILE")
        fMkdirDone = False 
        if not fMkdirDone:
            fMkdirDone = True
            os.mkdir(strAppData)
        strDir = "%s\\mycoinsss" %strAppData
    else:
        return "."

    if not os.path.exists(strDir):
        os.mkdir(strDir)

    return strDir


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
