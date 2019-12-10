import math
import hashlib
import os

def decode (k, EM, hLen):
    if (k < (2 * hLen + 2)):
        print ("WARNING: DECRYPTION ERROR; TERMINATION IMINENT")
        print ("TERMINATIING.....")
        exit()
    L = ''
    Y = EM[:4]
    maskedSeed = [4:4*hLen]
    maskedDB = [4*hLen:(k- hLen - 1)]
    seedMask = MGF (maskedDB, hLen)
    seed = maskedSeed^seedMask
    dbMask = MGF(seed,k - hLen - 1)
    DB = maskedDB^dbMask
    lHash = DB[:4*hLen]
    PS = DB[]

def encode (M, k, hLen):
    if (len(M) > (k - 2 * hLen - 2)):
        print ("message too long! Terminating process...")
        exit()
    L = ''
    PS = ''
    for i in range (0, (k-len(M)-2*hLen - 2)):
        PS += '0000'
    DB = lHash + PS + '0001' + M 
    os.urandom(hLen)
    dbMask = MGF(seed, k- hLen - 1)
    maskedDB = DB ^ dbMask
    seedMask = MGF (maskedDB, hLen)
    maskedSeed = seed ^ seedMask
    EM = '0000' + maskedSeed + maskedDB
    return EM

if __name__ == '__main__':
    seed = '1e652ec152d0bfcd65190ffc604c0933d0423381'
    M = 'fd5507e917ecbe833878'  

    k = 128
    hLen = 20

    EM = encode(M,k, hLen)

    M = decode(k, EM, hLen)

    # 18a65e36189833d99e55a68dedda1cce13a494c947817d25dc80d9b4586a
    # 1b0a6caec1c920a97fb89c634ccfd2ef5eeb6033

