from Crypto.Hash import SHA1, SHA256, SHA512
import keyderiv as kd
import timeit as t

## TIME IT VECTORS
'''
Input:
 P = "password" (8 octets)
 S = "salt" (4 octets)
 c = 4096
 dkLen = 20
Output:
 DK = c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d 96 28 93 a0
'''
expected = "c5e478d59288c841aa530db6845c4c8d962893a0"
minimum = t.timeit(lambda:
    kd.testVector(expected, kd.derMasterKey("password", "salt", 4096, 20, SHA256)), number=1
)
print(minimum)
# TODO: Time the actual key generation function not print statements

'''
Input:
 P = "password" (8 octets)
 S = "salt" (4 octets)
 c = 16777216
 dkLen = 20
Output:
 DK = cf 81 c6 6f e8 cf c0 4d 1f 31 ec b6 5d ab 40 89 f7 f1 79 e8


Input:
 P = "passwordPASSWORDpassword" (24 octets)
 S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
 c = 4096
 dkLen = 25
Output:
 DK = 34 8c 89 db cb d3 2b 2f 32 d8 14 b8 11 6e 84 cf
      2b 17 34 7e bc 18 00 18 1c


Input:
 P = "pass\0word" (9 octets)
 S = "sa\0lt" (5 octets)
 c = 4096
 dkLen = 16
Output:
 DK = 89 b6 9d 05 16 f8 29 89 3c 69 62 26 65 0a 86 87
'''