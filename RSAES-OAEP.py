import math
import hashlib
import os
import re

def I20SP (x:int, xLen: int)->bytes:
    if (x >=  pow(256, xLen)):
        print ("integer too large! Terminating process...")
        exit()
    return x.to_bytes(xLen, 'big')

def MGF1 (seed, maskLen):
    mgfSeedAsbytes = bytearray.fromhex(seed)
    if (maskLen > pow(2, 32)):
        print ("mask too long! Terminating process...")
        exit()
    T = ''
    x = 0
    while(len(T) < maskLen*2):
        C = I20SP(x, 4)
        concatedStrings = mgfSeedAsbytes + C
        sha1Hash = hashlib.sha1(concatedStrings)
        T += sha1Hash.hexdigest()
        x+=1
    return (T[:maskLen*2])


def decode (k, EM, hLen):
    if (k < (2 * hLen + 2)):
        print ("WARNING: DECRYPTION ERROR; TERMINATION IMINENT")
        print ("TERMINATIING.....")
        exit()
    L = ''
    Y = EM[:4]
    maskedSeed = EM[2:2 * hLen + 2]
    maskedDB = EM[2 + hLen * 2:]
    seedMask = bytearray.fromhex(MGF1 (maskedDB, hLen))
    seed = int(maskedSeed,16) ^ int.from_bytes(seedMask, byteorder='big', signed=False)
    dbMask = bytearray.fromhex(MGF1(hex(seed)[2:],k - hLen - 1))
    DB = hex(int(maskedDB, 16) ^ int.from_bytes(dbMask,byteorder='big', signed=False))
    lHash = DB[:4 * hLen]
    M = DB[DB[hLen*2:].index('01')  + hLen * 2 + 2:]
    return M

def encode (M, k, hLen, seed):
    if (len(M) > (k - 2 * hLen - 2)):
        print ("message too long! Terminating process...") 
        exit()
    L = ''
    PS = b''
    mAsBytes = bytearray.fromhex(M)
    for i in range (0, (k-len(mAsBytes)-2*hLen - 2)):
        PS += (0).to_bytes(1, 'big')
    lHash = hashlib.sha1(bytearray()).digest()
    DB = lHash + PS + (1).to_bytes(1, 'big') + mAsBytes
    dbMask = bytearray.fromhex(MGF1(seed, k- hLen - 1))
    maskedDB = int(DB.hex(),16) ^ int.from_bytes(dbMask, byteorder='big', signed=False)
    seedMask = bytearray.fromhex(MGF1 (hex(maskedDB)[2:], hLen))
    maskedSeed = int(seed,16) ^ int.from_bytes(seedMask, byteorder='big', signed=False)
    EM = (hex(maskedSeed)[2:] + hex(maskedDB)[2:]).rjust(256,'0')
    return EM

if __name__ == '__main__':
    #mgfSeed = '0123456789abcdef'
    hLen = 20  #Length of sha-1 hash is 20 octets (Bytes)
    #maskLen = 30 #Length of mask in octets (Bytes)


    print('MGF:' ,MGF1 ('ab61395aa98b49f0a6de254e933e391eb8', 30))
    

    #seed = '1e652ec152d0bfcd65190ffc604c0933d0423381'
    #M = 'fd5507e917ecbe833878'  

    k = 128
    
    EM = encode('0d4413b8823db607b594f3d7e86c4db168a4a17eb4fffd97bb71',k, hLen, 'e1683401d63da920ccced24b47c53cca7479f0ec')

    print ('EM =' , EM)

    M = decode(k, '00581bc2381cf79218566065eb1def452262df368e129de319b5c2bb66e84df6be244fc653a9468c6aafbe715fe366526e9596c452cdf7a42ddcec8d8005724dc7d9450b769aa0fe6f58e8949e503294de3106a7a3b0254eac2b94d245421e610ca70466137c29e7ff5ccd41dda83a44457ea3c820d0f360599833d34ec82e3b', hLen)

    print ('M =' ,M)