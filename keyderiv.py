from pbkdf2 import PBKDF2
from Crypto.Cipher import AES 
from Crypto.Hash import MD5, SHA, SHA256, SHA512, HMAC
from Crypto.Cipher import AES, DES3
import os
import random
import string

GlobalSalt = b"jeffmur@uw.edu"
# TODO: Change this

'''
@author: Jeffrey Murray Jr
@purpose: Generate a master key from user passphrase
'''

def randBytesOfLen(chars = string.ascii_uppercase + string.digits, N=16):
	return (''.join(random.choice(chars) for _ in range(N))).encode('utf-8')

def maxKeyCase(encryptAlgo):
    """
    Returns keys sizes based on encryption requirements
    Key must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
    """
    switch = {
        'AES128': 16,
        'AES256': 32,
        '3DES' : 100000 #TODO: later
    }

    return switch.get(encryptAlgo, -1)

def derMasterKey(Password, Salt, c, dkLen, hashAlgo):
    """
    @input:
        Password - phasephrase entered by user
        Salt - pseudo 
        TODO: comments
    """
    return PBKDF2(
        Password,
        Salt,
        c,
        hashAlgo,
        HMAC
    ).read(dkLen).hex().upper()


def derEncryptHMAC(masterKey, hashAlgo, encryptAlgo):
    """
    Using HMAC by default...
    """
    masterKey = masterKey.encode('ascii')

    keySize = maxKeyCase(encryptAlgo)

    return PBKDF2(
        masterKey,
        GlobalSalt,
        1,          # num of iterations
        hashAlgo,   # Choice of Crypto.Hash { SHA256 or SHA512 }
        HMAC        

    ).read(int(keySize/2)).hex().upper(), HMAC.new(masterKey, GlobalSalt, hashAlgo).digest().hex().upper()[:keySize]

def testVector(expected, reality):
    '''
    '''
    print('Comparing Hashes:')
    print(f' {expected.upper()} \n {reality}')
    print(f'HMAC-SHA256 Matches: {expected.upper() == reality.upper()}')
