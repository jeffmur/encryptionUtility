def maxKeyCase(encryptAlgo):
    """
    Returns keys sizes based on encryption requirements
    Key must be 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes long.
    """
    switch = {
        'AES128': 16,
        '3DES' : 24, # can be 16 or 24 bytes long
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