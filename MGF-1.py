import math
import hashlib

def I20SP (x:int, xLen: int)->bytes:
    if (x >=  pow(256, xLen)):
        print ("integer too large! Terminating process...")
        exit()
    newX = 0
    #int(str, base)
    x = str(x)
    if (len(x) < xLen):
        for j in range (0, xLen - len(x)):
            x = '0' + x 
    for i in range (1, xLen):
        newX += int(x[xLen-i] * pow(256, xLen-i))
    return str(newX)

if __name__ == '__main__':
    mgfSeed = '0123456789abcdef'
    maskLen = 30 #Length of mask in octets (Bytes)
    hLen = 20  #Length of sha-1 hash is 20 octets (Bytes)

    if (maskLen > pow(2, 32)):
        print ("mask too long! Terminating process...")
        exit()
    T = ''
    for counter in range (0, math.ceil(maskLen / hLen) - 1):
        C = I20SP(counter, 4)
        T += hashlib.sha1((mgfSeed + C).encode()).hexdigest()
    print (T[:maskLen*2])


    # 18a65e36189833d99e55a68dedda1cce13a494c947817d25dc80d9b4586a
    # 1b0a6caec1c920a97fb89c634ccfd2ef5eeb6033