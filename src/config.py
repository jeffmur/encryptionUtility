'''
Purpose: Configuration for shared variables
@author: Jeffrey Murray Jr
@date: 04/16/21
'''

'''
Plain Text Hashing Algorithm
Options: SHA256, SHA512
'''
plainHash = 'SHA512' 

'''
Master Key Length (in bytes)
Requirement: Must be greater than 32 bytes
'''
masterKeyLength = 64

'''
Plain Text Encryption Algorithm
Options: AES128, AES256, 3DES
'''
plainEncrypt = 'AES256'

'''
Input File Path (Plaintext -> Ciphertext)
Can be relative to dir or long path from root
Compabilitity: .txt,  
TODO: TEST other file types
'''
plainFile = 'cases/large.txt'

'''
Output File Path (Ciphertext -> Plaintext)
Can be relative to dir or long path from root
'''
cipherFile = 'large.txt.enc'

'''
KDF Iteration bounds
'''
minKDF = 512
maxKDF = 65536
defaultKDF = 4096