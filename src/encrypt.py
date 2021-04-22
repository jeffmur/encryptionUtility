from Crypto.Cipher import AES 
from Crypto.Hash import MD5, SHA1, SHA256, SHA512, HMAC
from Crypto.Cipher import AES, DES3

import src.keyderiv as kd
import src.cipher as c
import src.config as config

def encrypt(password, kdfIter):

    # Assign shared variables + file paths
    plainHash = config.plainHash
    plainEncrypt = config.plainEncrypt
    fileIn = config.plainFile
    fileOut = config.cipherFile

    # From input cryptography options
    hashAlgo = c.capability(plainHash)
    enAlgo = c.capability(plainEncrypt)
    blockSize = c.blockSize(plainEncrypt)

    # 1) Create a master key with C iterations, 
    masterSalt = kd.randBytesOfLen(N=32)
    masterKey = kd.derMasterKey(password, masterSalt, kdfIter, config.masterKeyLength, hashAlgo)
    print(f'Master Key \t : {kd.pp(masterKey)} ')

    # 2) Derive encryption and HMAC from master key (based on encryption algorithm)
    # With two different fixed strings
    encryptSalt = kd.randBytesOfLen(N=32)
    hmacSalt = kd.randBytesOfLen(N=32)

    # Gen Keys w/ added salts
    encryptKey, hmacKey = kd.derEncryptHMAC(masterKey, hashAlgo, plainEncrypt, encryptSalt, hmacSalt)

    print(f' |> Encryption \t : {kd.pp(encryptKey)}')
    print(f' |> HMAC  \t : {kd.pp(hmacKey)}')

    # 3) Encrypt your data using CBC chaining mode w/ 3DES, AES128, AES256
    ## Key must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
    iv = kd.randBytesOfLen(N=enAlgo.block_size)
    cipher = enAlgo.new(encryptKey, enAlgo.MODE_CBC, iv)

    # Input File (ALL OF IT)
    input = open(fileIn, 'rb')
    raw_data = input.read()
    input.close()

    # Encryption and padding
    pad_size, padded_data = c.paddingBy(blockSize, raw_data)
    cipherText = cipher.encrypt(padded_data)
    bcrypt = bytes(cipherText)

    print(f'Length of bcrypt: {len(bcrypt)}')

    # 4) Create an HMAC of the IV and encrypted data
    cia = HMAC.new(key=hmacKey, msg=iv+bcrypt, digestmod=hashAlgo).hexdigest().upper()

    # Meta Data Header as Dictionary
    header ={   'HASH' : plainHash, 
                'CIPHER': plainEncrypt, 
                'MASTER': config.masterKeyLength,
                'IV': iv.decode('utf-8'),
                'KDF' : kdfIter, 
                'INTEGRITY': cia, 
                'MSALT': masterSalt.decode('utf-8'),
                'HSALT': hmacSalt.decode('utf-8'),
                'ESALT': encryptSalt.decode('utf-8'),
                'PAD': pad_size
            }

    bitHeader = c.dict_to_bits(header)

    # Write to File
    output = open(fileOut, 'wb')
    output.write(bitHeader)
    output.write(bcrypt)
    output.close()

    print(f'\n--- new file {fileOut} --- \n Hash: {plainHash} \n Encryption: {plainEncrypt} \n IV: {iv} \n Integrity: {cia} ')
    print('--- EOF ---')