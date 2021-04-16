from pbkdf2 import PBKDF2
from Crypto.Cipher import AES 
from Crypto.Hash import MD5, SHA, SHA256, SHA512, HMAC
from Crypto.Cipher import AES, DES3
import os
import random
import string

import src.cipher as c

GlobalSalt = b"jeffmur@uw.edu"
# TODO: Change this

'''
@author: Jeffrey Murray Jr
@purpose: Generate a master key from user passphrase
'''

def randBytesOfLen(chars = string.ascii_uppercase + string.digits, N=16):
	return (''.join(random.choice(chars) for _ in range(N))).encode('utf-8')

def pp(key):
    '''
    Pretty print keys as uppercase hex
    '''
    return key.hex().upper()

def derMasterKey(Password, Salt, c, dkLen, ptHashAlgo):
    """
    @input: 
        Password - phasephrase entered by user 
        Salt - pseudo 
        Iterations - Strength 
        Key Length - TODO 
        Hash Algorithm - in plaintext - SHA256, SHA512 
    """
    return PBKDF2(
        Password,
        Salt,
        c,
        ptHashAlgo,
        HMAC
    ).read(dkLen) #.hex().upper().encode('ascii')


def derEncryptHMAC(masterKey, hashAlgo, encryptAlgo):
    """
    Purpose: Derives two keys from master secret key 
    @input: 
        masterKey   : Shared Secret -> derived from -> password + salt 
        hashAlgo    : Cryptographic Strength for KDF 
        encryptAlgo : Cryptographic Strength for Ciphertext (see maxKeyCase())
    """
    keySize = c.maxKeyCase(encryptAlgo)

    return PBKDF2(
        masterKey,
        GlobalSalt,
        1,          # num of iterations
        hashAlgo,   # Choice of Crypto.Hash { SHA256 or SHA512 }
        HMAC        

    ).read(int(keySize/2)), HMAC.new(masterKey, GlobalSalt, hashAlgo).digest()

# def testVector(expected, reality):
#     '''
#     '''
#     print('Comparing Hashes:')
#     print(f' {expected.upper()} \n {reality}')
#     print(f'HMAC-SHA256 Matches: {expected.upper() == reality.upper()}')
