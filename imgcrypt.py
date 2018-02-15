import hashlib
import numpy as np
import binstr
import binascii
import os

# Block size = 4 bytes
LT=4

#SBOX=np.empty([LT,LT])
#Eky=np.empty(32)
SBOX=[[""]*LT]*LT
TBOX=[[""]*LT]*LT
W=[bin(0)[2:].zfill(8) for x in range(4)]
Eky=[""]*32
Ky=np.empty(100)

E=[]*LT

def encryption_key_gen(Ky,D):
    p1=p2=p3=0
    L1=len(Ky)
    for i in range(0,32):
        if(i%2==0):
            Eky[i]=D[p1]
            p1+=1
            print "Eky[%d] = %s\n"%(i,Eky[i])
        else:
            Eky[i]=binstr.b_xor(binstr.b_xor(D[p2],D[++p2]),Ky[(p3)%L1])
            p3+=1
            print "Eky[%d] = %s\n"%(i,Eky[i])
    return Eky

def SBOX_generation(Eky):
    p=0
    for i in range(0,LT):
        for j in range(0,LT):
            SBOX[i][j]=Eky[p]
            p=p+1

def TBOX_generation(Eky):
    p=16
    for i in range(0,LT):
        for j in range(0,LT):
            TBOX[i][j]=Eky[p]
            p=p+1

def WORD_generation(SBOX):
    for i in range(0,LT):
        for j in range(0,LT):
            W[i]=binstr.b_xor(W[i],SBOX[i][j])

def Transposition_Index_Generation(TBOX,j):
    TIndex=0
    for i in range(0,LT):
        TIndex=TIndex<<i
        TIndex=int(binstr.b_or(bin(TIndex)[2:].zfill(8),TBOX[j][i]),2)
    return TIndex


Key=raw_input("Enter key >=16 bytes: \n")

s=bytearray()
s.extend(Key)

Ky=[bin(x)[2:].zfill(8) for x in s]

#print "Ky:   ",Ky

Digest_string=hashlib.md5(Key).hexdigest()
b=bytearray.fromhex(Digest_string)
D=[bin(x)[2:].zfill(8) for x in b]
print "Digest_string =",Digest_string
print D

encryption_key_gen(Ky,D)
SBOX_generation(Eky)
TBOX_generation(Eky)
WORD_generation(SBOX)

print Transposition_Index_Generation(TBOX,0)

print "SBOX:  ",SBOX
print "TBOX:  ",TBOX
print "W:   ",W

#print "Binary digest length: ",len(bin(int(Digest_string,16))[2:].zfill(8))
#binascii gives correct length of 16 bytes for md5
#print "Binascii : ",binascii.unhexlify(Digest_string)
#print "Length of binary:  ",len(''.join('{0:08b}'.format(ord(x),'b')for x in Digest_string))

# N = size of bmp image in bytes - will always be a multiple of 4
statinfo=os.stat('lena_gray.bmp')
# gives size of file in bytes
# can also use os.path.getsize("lena_gray.bmp")
N=statinfo.st_size

IndexArray=[0]*N
SrtB=[0]*LT

# storing the contents bmp into byte array
# every element in byte array in one byte long
# we consider groups of LT bytes together for encryption i.e LT=4
with open("lena_gray.bmp", "rb") as imageFile:
    f=imageFile.read()
    S=bytearray(f)

# sending first 4 bytes
#Encrypt(S)
#print "Even parity test - ",EvenParity(binstr.b_xor(W[0],bin(S[0])[2:].zfill(8)))," W[0] = ",W[0]," S[0] ",bin(S[0])[2:].zfill(8)
