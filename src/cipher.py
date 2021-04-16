import math
from Crypto.Cipher import AES 
from Crypto.Hash import MD5, SHA, SHA256, SHA512, HMAC
from Crypto.Cipher import AES, DES3

import json

def dict_to_bits(the_dict):
    str = json.dumps(the_dict)
    return str.encode('utf-8')


def fetchHeaderFromFile(bitFile):
    '''
    Returns offsets (in bits)
            header (dict)
    '''
    header = (str(bitFile.read()).split("}")[0] + "}")[2:]
    offset = len(header)

    return offset, json.loads(header)  

def capability(plainAlgo):
    '''
    '''
    switch = {
        # Cipher
        'AES128': AES,
        '3DES' : DES3, 
        'AES256': AES,
        # Hashing
        'SHA256': SHA256,
        'SHA512': SHA512,
    }

    return switch.get(plainAlgo, None)

def maxKeyCase(encryptAlgo):
    """
    Returns keys sizes based on encryption requirements
    Key must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
    """
    switch = {
        'AES128': 16,
        '3DES' : 32, # can be 16 or 24 bytes long
        'AES256': 32,
    }

    return switch.get(encryptAlgo, -1)


def blockSize(encryptAlgo):
    """
    Returns blockSize for encryption Algorithm, allows for plug n play
    """
    switch = {
        'AES128': 16,
        '3DES' : 8, 
        'AES256': 16,
    }

    return switch.get(encryptAlgo, 16)

def round_near_base(x, base=5):
    return base * math.ceil(x/base)

def paddingBy(block, text):
    '''
    Input String of Text (block or line)
    Output: padded byte[]
    '''
    size = len(text)
    # Next multiple of block_size to pad w/ 0
    nextMultiple = round_near_base(size, block)
    # Pad with incrementing values
    padString = ''.join(['-' for x in range(0, nextMultiple-size)])

    print(f'Length: {size} \n next muliple of {block} is {nextMultiple} \n after padString: {padString}')
    return (text+padString).encode('utf-8')