'''
Purpose: User Interface for Encryption Options
'''
import src.keyderiv as keys
import src.cipher as cipher 
import src.config as config
from src.encrypt import encrypt
from src.decrypt import decyrpt
from getpass import getpass
import os

def checkInputPath(promptStatement, action):
    '''
    Immediate check for correct path entry (input and output entries)
    Purpose: Allows for a redo incase of typo
    Recursive for simplicity
    '''
    while(True):
        raw = input(promptStatement)
        if(action == 'Input'):
            if(os.path.isfile(raw)):
                return raw
            else:
                print('Error: Bad Input File! Please try again.')
        else:
            return raw

def welcomeStatement():
    print('Welcome to Encryption Utility \n@author Jeffrey Murray Jr')
    print('0: Exit')
    print('1: Encrypt a file')
    print('2: Decrypt a file')
    print('3: Modify Cryptography Configuration')
    return input('Choose Option: ')

def userEncrypt():
    config.plainFile = checkInputPath("Plaintext Path (relative): ", 'Input')
    config.cipherFile = checkInputPath("Ciphertext Path (relative): ", 'Output')
    passPhrase = getpass(prompt='Password (secret): ')
    print('\n---- Encrypting ----')
    encrypt(passPhrase, config.defaultKDF)

def userDecrypt():
    config.cipherFile = checkInputPath("Ciphertext Path (relative): ", 'Input')
    config.plainFile = checkInputPath("Plaintext Path (relative): ", 'Output')
    passPhrase = getpass('Password (shared-secret): ')
    print('\n---- Decrypting ----')
    decyrpt(passPhrase)

def modifyConfig():
    '''
    Error Handling at User Interface 
    - Incompatible algo
    - insufficent parameters
    - boundry for iteration
    '''
    tmp = input('Encryption Algorithm {AES128, AES256, 3DES}: ')
    config.plainEncrypt = tmp if cipher.capability(tmp) else 'AES256'

    tmp = input('Hashing Algorithm {SHA256, SHA512}: ')
    config.plainHash = tmp if cipher.capability(tmp) else 'SHA512'
    
    tmp = int(input('Master Key Length (must be between 32 and 256 bytes): '))
    config.masterKeyLength = tmp if (tmp >= 32 and tmp <=256) else 64

    tmp = int(input(f'KDF Iterations (must be between {config.minKDF} and {config.maxKDF}): '))
    config.defaultKDF = tmp if (tmp >= config.minKDF and tmp <= config.maxKDF) else 4096

def dispatchOption(inputOption):
    '''
    Ensure that the InputFile exists
    Before user enters outPath and Password
    '''
    i = int(inputOption)

    if(i == 0):
        return False
    elif(i == 1):
        userEncrypt()
    elif(i == 2):
        userDecrypt()
    elif(i == 3):
        modifyConfig()
    else:
        return welcomeStatement()
    print('\n')
    return True

# # # MAIN Function # # #
# Keep options available until exit

keepAlive = True
while(keepAlive):
    keepAlive = dispatchOption(welcomeStatement())

