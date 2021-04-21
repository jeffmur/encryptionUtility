## DECRYPTION TEST
from sys import hash_info, maxsize
from Crypto.Cipher import AES, DES3
from Crypto.Hash import SHA256, SHA512, HMAC
import src.cipher as c 
import src.keyderiv as kd 
import src.config as config
import os

def decyrpt(password):
    # From Configuration File
    fileIn = config.cipherFile

    # Fetch header & Serialize to string var
    bitFile = open(fileIn, 'rb+')
    offset, header = c.fetchHeaderFromFile(bitFile)
    tsize = os.fstat(bitFile.fileno()).st_size - offset
    bitFile.seek(offset)

    bcrypt = bitFile.read(tsize) #TODO: Len of file - offset ,,, ish+
    print(len(bcrypt))
    bitFile.close()

    # Fetch Algorithm Modules & Class Objects from header
    iv = str(header["IV"]).encode('utf-8')
    hashAlgo = c.capability(header["HASH"])
    decAlgo = c.capability(header["CIPHER"])
    integrityCheck = header["INTEGRITY"]
    config.masterKeyLength = header['MASTER']
    kdfIter = header["KDF"]
    masterSalt = str(header["MSALT"]).encode('utf-8')
    hmacSalt = str(header["HSALT"]).encode('utf-8')
    encryptSalt = str(header["ESALT"]).encode('utf-8')
    pad_size = int(header["PAD"])

    print(f"--- Reading File: {fileIn} ---")
    print(f' Hash: {header["HASH"]} \n Encryption: {header["CIPHER"]} \n IV: {iv} \n Integrity: {integrityCheck} \n')

    print("--- Generated Keys ---")

    masterKey = kd.derMasterKey(password, masterSalt, kdfIter, config.masterKeyLength, hashAlgo)
    encryptKey, hmacKey = kd.derEncryptHMAC(masterKey, hashAlgo, header['CIPHER'], encryptSalt, hmacSalt)

    print(f'Master Key \t : {kd.pp(masterKey)} ')
    print(f' |> Encryption \t : {kd.pp(encryptKey)}')
    print(f' |> HMAC  \t : {kd.pp(hmacKey)}')

    cia = HMAC.new(key=hmacKey, msg=iv+bcrypt, digestmod=hashAlgo).hexdigest().upper()

    if(cia != integrityCheck):
        raise ValueError(f'ERROR: Cannot decrypt file \n |> Local : {cia} \n |> Source: {integrityCheck}')

    toPlain = decAlgo.new(encryptKey, decAlgo.MODE_CBC, iv)
    text = toPlain.decrypt(bcrypt)

    # print(text)
    outFile = config.plainFile
    file = open(outFile, 'w')
    file.write(text.decode('utf-8'))

    # Remove padding and close
    file.seek(0, 2)              # seek to end of file; f.seek(0, os.SEEK_END) is legal
    file.seek(file.tell() - pad_size, 0)  # seek to the second last char of file; f.seek(f.tell()-2, os.SEEK_SET) is legal
    file.truncate()
    file.close()

    # TODO: remove() all padding...
    '''
    import os

    with open(filename, 'rb+') as filehandle:
        filehandle.seek(-1, os.SEEK_END)
        filehandle.truncate()
    '''

    print(f'--- New File: {outFile} ---')