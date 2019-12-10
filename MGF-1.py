import math
import hashlib

def I20SP (x:int, xLen: int)->bytes:
    if (x >=  pow(256, xLen)):
        print ("integer too large! Terminating process...")
        exit()
    return x.to_bytes(xLen, 'big')

if __name__ == '__main__':
    mgfSeed = '0123456789abcdef'
    mgfSeedAsbytes = bytearray.fromhex(mgfSeed)
    maskLen = 30 #Length of mask in octets (Bytes)
    hLen = 20  #Length of sha-1 hash is 20 octets (Bytes)

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
    print (T[:maskLen*2])
    # 18a65e36189833d99e55a68dedda1cce13a494c947817d25dc80d9b4586a
