from pbkdf2 import PBKDF2
from Crypto.Cipher import AES 
from Crypto.Hash import MD5, SHA1, SHA256, SHA512, HMAC
from Crypto.Cipher import AES, DES3
import os

import src.keyderiv as kd
import src.cipher as c

'''
@ Parameters: 
    Password
    Salt
    Hash Algorithm
'''

hashAlgo = SHA256
plainEncrypt = '3DES'
enAlgo = DES3 if plainEncrypt == '3DES' else AES
blockSize = c.blockSize(plainEncrypt)

password = b"password"
salt = kd.GlobalSalt #kd.randBytesOfLen(N=32)

print(f'Salt \t \t : {salt} \n')

# 1) Create a master key with C iterations, 
# Todo: identify what dklen needs to be
masterKey = kd.derMasterKey(password, salt, 4096, 32, hashAlgo)
print(f'Master Key \t : {kd.pp(masterKey)} ')


# 2) Derive encryption and HMAC from master key (based on encryption algorithm)
# Todo: Add 3DES capability
encryptKey, hmacKey = kd.derEncryptHMAC(masterKey, hashAlgo, 'AES256')
print(f' |> Encryption \t : {kd.pp(encryptKey)}')
print(f' |> HMAC  \t : {kd.pp(hmacKey)}')

# 3) Encrypt your data using CBC chaining mode w/ 3DES, AES128, AES256
# Todo: File input capability
## ENCRYPTION
## Key must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.

iv = kd.randBytesOfLen(N=blockSize) # always 16 bytes

cipher = enAlgo.new(encryptKey, enAlgo.MODE_CBC, iv)

# Block Size & IV are constant mulitples of 16
# TODO: Padding for AES, DES not not care :)
testText = b"mustbeamultiof16doesDES?"

crypt = iv + cipher.encrypt(testText)

# 4) Create an HMAC of the IV and encrypted data
integrity = HMAC.new(key=iv, msg=crypt, digestmod=hashAlgo).hexdigest()

header = {'HASH' : hashAlgo, 'CIPHER': enAlgo, 'INTEGRITY': integrity}

print(f'\n --- new file --- \n Hash: {hashAlgo.__name__} \n Encryption: {enAlgo.__name__} \n IV: {iv} \n Integrity: {integrity} ')
print(f'{crypt} \n --- EOF --- \n')

# DECRYPTION TEST
plain = enAlgo.new(encryptKey, enAlgo.MODE_CBC, iv)

print(plain.decrypt(crypt)[blockSize:])

