from Crypto.Hash import SHA1, SHA256, SHA512
import src.keyderiv as kd
import timeit as t
'''
Purpose: Time it test vectors and validation for PBKDF2-HMAC-SHA 256/512
Functionality: Tests both cipher modes, and returns time to run 1 round of key derivations

## Sources: https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors 
##          https://github.com/Anti-weakpasswords/PBKDF2-Test-Vectors/releases
'''

def timeVector(P, S, c, dkLen, cipher, iter):
    '''Time key derivation'''
    return t.timeit(lambda: kd.derMasterKey(P, S, c, dkLen, cipher), number = iter
)

def handler(exp, deriveKeyFunc, time):
    '''Pretty Print Functionality to keep consistency'''
    exp = exp.replace(" ", "").upper()
    out = deriveKeyFunc.hex().upper()
    # Print result
    print(f"Expected\t: {exp} \nGenerated\t: {out}")
    print(f"Time Elapsed: {time} sec")

def prettyPrint(P, S, c, dkLen, cipher, iter, exp):
    print(f"{P}, {S}, dkLen: {dkLen}")
    handler(
        exp, 
        kd.derMasterKey(P, S, c, dkLen, cipher),
        timeVector(P, S, c, dkLen, cipher, iter)
    )

# --------------------------------- PBKDF2-HMAC-SHA256 ---------------------------------
print("---\n--- Test Vectors for SHA256 ---\n---")

# Input:
P = "password" 
S = "salt" 
c = 4096
dkLen = 20
# Output:
DK = "c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d 96 28 93 a0"
'''
Results:
    Expected        : C5E478D59288C841AA530DB6845C4C8D962893A0 
    Generated       : C5E478D59288C841AA530DB6845C4C8D962893A0 
    Time Elapsed: 0.1568798 sec
'''
# Generate output
prettyPrint(P, S, c, dkLen, SHA256, 1, DK)


# Input:
P = "passwordPASSWORDpassword" 
S = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
c = 4096
dkLen = 25
# Output:
DK = "34 8c 89 db cb d3 2b 2f 32 d8 14 b8 11 6e 84 cf 2b 17 34 7e bc 18 00 18 1c"
'''
Results:
    Expected        : 348C89DBCBD32B2F32D814B8116E84CF2B17347EBC1800181C 
    Generated       : 348C89DBCBD32B2F32D814B8116E84CF2B17347EBC1800181C 
    Time Elapsed: 0.1535361 sec
'''
prettyPrint(P, S, c, dkLen, SHA256, 1, DK)


# Input:
P = "pass\0word"
S = "sa\0lt" 
c = 4096
dkLen = 16
# Output:
DK = "89 b6 9d 05 16 f8 29 89 3c 69 62 26 65 0a 86 87"
'''
Results:
    Expected        : 89B69D0516F829893C696226650A8687 
    Generated       : 89B69D0516F829893C696226650A8687 
    Time Elapsed: 0.15707639999999995 sec
'''
prettyPrint(P, S, c, dkLen, SHA256, 1, DK)


# Input:
P = "password" 
S = "salt" 
c = 65536
dkLen = 20
# Output:
DK = "41 56 f6 68 bb 31 db 3a 17 f4 d1 b9 14 24 ef 0d 41 7a d1 f3"
'''
Results:
    Expected        : 4156F668BB31DB3A17F4D1B91424EF0D417AD1F3 
    Generated       : 4156F668BB31DB3A17F4D1B91424EF0D417AD1F3 
    Time Elapsed: 2.6446893000000005 sec
'''
# Generate output
prettyPrint(P, S, c, dkLen, SHA256, 1, DK)

# Input:
P = "passwordPASSWORDpassword" 
S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" 
c = 100000
dkLen = 8
# Output:
DK = "af 70 dc 8C e4 cc c6 d3"
'''
Results:
    Expected        : AF70DC8CE4CCC6D3
    Generated       : AF70DC8CE4CCC6D3
    Time Elapsed: 3.8354648000000005 sec
'''
prettyPrint(P, S, c, dkLen, SHA256, 1, DK)

# --------------------------------- PBKDF2-HMAC-SHA512 ---------------------------------
print("---\n--- Test Vectors for SHA512 ---\n---")

# Input:
P = "password" 
S = "salt" 
c = 1
dkLen = 64
# Output:
DK = "867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE"
'''
Results:
    Expected        : 867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE 
    Generated       : 867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE 
    Time Elapsed: 5.040000000011702e-05 sec
'''
prettyPrint(P, S, c, dkLen, SHA512, 1, DK)

# Input:
P = "password" 
S = "salt" 
c = 2
dkLen = 64
# Output:
DK = "E1D9C16AA681708A45F5C7C4E215CEB66E011A2E9F0040713F18AEFDB866D53CF76CAB2868A39B9F7840EDCE4FEF5A82BE67335C77A6068E04112754F27CCF4E"
'''
Results:
    Expected        : E1D9C16AA681708A45F5C7C4E215CEB66E011A2E9F0040713F18AEFDB866D53CF76CAB2868A39B9F7840EDCE4FEF5A82BE67335C77A6068E04112754F27CCF4E 
    Generated       : E1D9C16AA681708A45F5C7C4E215CEB66E011A2E9F0040713F18AEFDB866D53CF76CAB2868A39B9F7840EDCE4FEF5A82BE67335C77A6068E04112754F27CCF4E 
    Time Elapsed: 8.759999999963242e-05 sec
'''
prettyPrint(P, S, c, dkLen, SHA512, 1, DK)


# Input:
P = "password" 
S = "salt" 
c = 4096
dkLen = 64
# Output:
DK = "D197B1B33DB0143E018B12F3D1D1479E6CDEBDCC97C5C0F87F6902E072F457B5143F30602641B3D55CD335988CB36B84376060ECD532E039B742A239434AF2D5"
'''
Results:
    Expected        : D197B1B33DB0143E018B12F3D1D1479E6CDEBDCC97C5C0F87F6902E072F457B5143F30602641B3D55CD335988CB36B84376060ECD532E039B742A239434AF2D5 
    Generated       : D197B1B33DB0143E018B12F3D1D1479E6CDEBDCC97C5C0F87F6902E072F457B5143F30602641B3D55CD335988CB36B84376060ECD532E039B742A239434AF2D5 
    Time Elapsed: 0.16104560000000046 sec
'''
prettyPrint(P, S, c, dkLen, SHA512, 1, DK)


# Input:
P = "passwordPASSWORDpassword" 
S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" 
c = 4096
dkLen = 64
# Output:
DK = "8C0511F4C6E597C6AC6315D8F0362E225F3C501495BA23B868C005174DC4EE71115B59F9E60CD9532FA33E0F75AEFE30225C583A186CD82BD4DAEA9724A3D3B8"
'''
Results:
    Expected        : 8C0511F4C6E597C6AC6315D8F0362E225F3C501495BA23B868C005174DC4EE71115B59F9E60CD9532FA33E0F75AEFE30225C583A186CD82BD4DAEA9724A3D3B8 
    Generated       : 8C0511F4C6E597C6AC6315D8F0362E225F3C501495BA23B868C005174DC4EE71115B59F9E60CD9532FA33E0F75AEFE30225C583A186CD82BD4DAEA9724A3D3B8 
    Time Elapsed: 0.15111249999999998 sec
'''
prettyPrint(P, S, c, dkLen, SHA512, 1, DK)


# Input:
P = "passwordPASSWORDpassword" 
S = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
c = 65536
dkLen = 64
# Output:
DK = "C2D9C4D4AC4AB13DA3A7F7C25A21FF653F498E91FD9D838838BBA4E7BD67DEDC5CE3FE3873952BF287E3676EE8D861F1D258CAFF12C81154D602A8E8F707D649"
'''
Results:
    Expected        : C2D9C4D4AC4AB13DA3A7F7C25A21FF653F498E91FD9D838838BBA4E7BD67DEDC5CE3FE3873952BF287E3676EE8D861F1D258CAFF12C81154D602A8E8F707D649 
    Generated       : C2D9C4D4AC4AB13DA3A7F7C25A21FF653F498E91FD9D838838BBA4E7BD67DEDC5CE3FE3873952BF287E3676EE8D861F1D258CAFF12C81154D602A8E8F707D649 
    Time Elapsed: 2.5294178 sec
'''
prettyPrint(P, S, c, dkLen, SHA512, 1, DK)


# Input:
P = "passwordPASSWORDpassword"
S = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
c = 100000
dkLen = 8
# Output:
DK = "07550606F4096F6B"
'''
Results:
    Expected        : 07550606F4096F6B
    Generated       : 07550606F4096F6B
    Time Elapsed: 3.8352485000000005 sec
'''
prettyPrint(P, S, c, dkLen, SHA512, 1, DK)