from pbkdf2 import PBKDF2
from Crypto.Cipher import AES 
from Crypto.Hash import MD5, SHA1, SHA256, SHA512, HMAC
from Crypto.Cipher import AES, DES3
import keyderiv as kd
import os

## KEY DERIVATION

password = b"password"
salt = kd.randBytesOfLen(N=32)

print(f'Salt \t \t : {salt} \n')

# print(encodeKey)

digmod = SHA1
blocksize = 16 # in bytes

masterKey = kd.derMasterKey(password, salt, 4096, 32, SHA256)
print(f'Master Key \t : {masterKey} ')

encryptKey, hmacKey = kd.derEncryptHMAC(masterKey, SHA256, 'AES256')

print(f' |> Encryption \t : {encryptKey}')
print(f' |> HMAC  \t : {hmacKey}')

## ENCRYPTION
## Key must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.

iv = kd.randBytesOfLen(N=AES.block_size) # always 16 bytes

test = AES.new(encryptKey.encode('ascii'), AES.MODE_CBC, iv)

# Block Size & IV are constant mulitples of 16
testText = b"mustbeamultiof16"
print(len(testText))

crypt = iv + test.encrypt(testText)

print(crypt)