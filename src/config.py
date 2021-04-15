'''
Purpose: User Interface for Encryption Options
'''
import keyderiv as kd
import cipher as c 
import sys


args = sys.argv

if len(args) != 4:
    print(f"Usage: py3 welcome.py Encryption Algorithm, Hashing Algorithm, Iterations for KDF")
    print(" | Encryption Algorithms : AES128, AES256, 3DES")
    print(" | Hashing Algorithms    : SHA256, SHA512")
    print(" | Iteration Range (1 - 69096)")
    # TODO: Performance for iterations
    exit()