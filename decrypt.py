## DECRYPTION TEST
from sys import hash_info, maxsize
from Crypto.Cipher import AES, DES3

from Crypto.Hash import SHA256, SHA512
import src.cipher as c 
import src.keyderiv as kd 

fileIn = 'large.txt.enc'
password = b"password"
salt = kd.GlobalSalt #kd.randBytesOfLen(N=32)

bitFile = open(fileIn, 'rb+')

# Fetch header & Serialize to string var
offset, header = c.fetchHeaderFromFile(bitFile)
bitFile.seek(offset)

all = bitFile.read(30000) #TODO: Len of file - offset ,,, ish
bitFile.close()

# # Fetch Algorithm Modules & Class Objects
# #! Header + HMAC + IV + SALT(s) + ENCRYPTED DATA 
iv = str(header['IV']).encode('utf-8')
hashAlgo = c.capability(header["HASH"])
decAlgo = c.capability(header["CIPHER"])
integrity = header["INTEGRITY"]

# Calculate blockSize (from encryption algorithm)
blockSize = c.blockSize(decAlgo)

print(f"--- Reading File: {fileIn} ---")
print(f'Hash: {header["HASH"]} \n Encryption: {header["CIPHER"]} \n IV: {iv} \n Integrity: {integrity} \n')

print("--- Generated Keys ---")
masterKey = kd.derMasterKey(password, salt, 4096, 32, hashAlgo)
encryptKey, hmacKey = kd.derEncryptHMAC(masterKey, hashAlgo, '3DES')

print(f'Master Key \t : {kd.pp(masterKey)} ')
print(f' |> Encryption \t : {kd.pp(encryptKey)}')
print(f' |> HMAC  \t : {kd.pp(hmacKey)}')

toPlain = decAlgo.new(encryptKey, decAlgo.MODE_CBC, iv)
text = toPlain.decrypt(all)

# print(text)
outFile = fileIn[:-4]
file = open(outFile, 'w')
file.write(text.decode('utf-8'))
file.close()

print(f'--- New File: {outFile} ---')