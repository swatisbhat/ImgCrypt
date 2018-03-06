# libraries used
import hashlib
import binstr
import numpy 
import os
from PIL import Image
import scipy.misc
import re

# Block size = 4 bytes
LT = 4

# SBOX and TBOX Initialisation
SBOX = [['' for i in range(LT)] for j in range(LT)]
TBOX = [['' for i in range(LT)] for j in range(LT)]

# Word array Initialisation ( required for encryption )
W = [bin(0)[2:].zfill(8) for x in range(4)]

# Key used to generate SBOX and TBOX
Eky = ['' for i in range(32)]

# Key used to generate SBOX and TBOX for decryption
Eky_d = ['' for i in range(32)]

# SBOX and TBOX Initialisation for decryption
SBOX_d = [['' for i in range(LT)] for j in range(LT)]
TBOX_d = [['' for i in range(LT)] for j in range(LT)]

# Word array initialisation for decryption
W_d = [bin(0)[2:].zfill(8) for x in range(4)]

# User input key ( >= 16 Bytes )
Ky = []

# User input key for decryption
Ky_d = []

def encryption_key_gen(EKy, Ky, D):
    '''
    Generates 32 Bytes EKy from user input Ky ( >= 16 Bytes ) 
    and D ( MD5 hash of Ky = 16 Bytes )
    '''
    p1 = p2 = p3 = 0
    L1 = len(Ky)
    for i in range(0, 32):
        if(i % 2 == 0):
            Eky[i] = D[p1]
            p1 += 1
        else:
            p4 = p2 + 1
            Eky[i] = binstr.b_xor(binstr.b_xor(D[p2], D[p4]), Ky[(p3) % L1])
            p3 += 1
    return Eky


def SBOX_generation(SBOX, Eky):
    '''
    Generates LT x LT SBOX using EKy
    '''
    p = 0
    for i in range(0, LT):
        for j in range(0, LT):
            SBOX[i][j] = Eky[p]
            p = p + 1


def TBOX_generation(TBOX, Eky):
    '''
    Generates LT x LT TBOX using EKy
    '''
    p = 16
    for i in range(0, LT):
        for j in range(0, LT):
            TBOX[i][j] = Eky[p]
            p = p + 1


def WORD_generation(SBOX, W):
    '''
    Generates of 1 x LT WORD array by column wise XORing of SBOX 
    ( used for encryption )
    '''
    for i in range(0, LT):
        for j in range(0, LT):
            W[i] = binstr.b_xor(W[i], SBOX[j][i])


def transposition_index_generation(TBOX, j):
    '''
    Used for transposition of ciphered Bytes among N places
    ( N - size of secret file ) using TBOX
    '''
    TIndex = 0
    for i in range(0, LT):
        TIndex = TIndex << i
        TIndex = int(binstr.b_or(bin(TIndex)[2:].zfill(8), TBOX[j][i]), 2)
    return TIndex


def EvenParity(s):
    '''
    Checks if string s has even parity
    '''
    count = 0
    for i in s:
        if(i == '1'):
            count += 1
    if(count % 2 == 0):
        return True
    else:
        return False

def Rotate_Right(j, SBOX):
    SBOX[j] = [str(x) for x in numpy.roll(SBOX[j], 1)]

def Rotate_Left(j, SBOX):
    SBOX[j] = [str(x) for x in numpy.roll(SBOX[j], -1)]

def Transpose(SBOX):
    SBOX = zip(*SBOX) 

def Encrypt(S, SE, SBOX, TBOX, IndexArray, SrtB):
    E = ['' for i in range(4)]
    for i in range(0, LT - 1):
        for j in range(0, LT):
            E[j] = binstr.b_xor(W[j], S[j])
        for j in range(0, LT):
            if(EvenParity(E[j]) == True):
                Rotate_Right(j, SBOX)
            else:
                Rotate_Left(j, SBOX)
                

            SBOX[2][j] = binstr.b_xor(SBOX[2][j], bin(SrtB[j])[2:].zfill(8))

        Transpose(SBOX)
        E = [str(x) for x in numpy.roll(E, 1)]

    for i in range(0, LT):
        TIndex = transposition_index_generation(TBOX, i)
        while(IndexArray[TIndex % N] != 0):
            TIndex = TIndex + 1
        TIndex = TIndex % N
        #write E[i] in encrypted file SE in position of TIndex
        SE[TIndex] = int(E[i],2)
        IndexArray[TIndex] = 1
        SrtB[i] = int(S[i],2)

    SBOX, TBOX = TBOX, SBOX
    return SE, SBOX, TBOX


def Decrypt(SE, SD, SBOX_d, TBOX_d, IndexArray_d, SrtB_d, Ky_d):
    L1 = len(Ky_d)
    digest_string_in_hex = hashlib.md5(Ky).hexdigest()
    digest_string = bytearray.fromhex(digest_string_in_hex)
    D = [bin(x)[2:].zfill(8) for x in digest_string]
    Eky1_d = encryption_key_gen(Eky_d, Ky_d, D)
    SBOX_generation(SBOX_d, Eky1_d)

    # calculate total number of bytes in image SE = N_d

    IndexArray_d = [0] * N_d
    SrtB_d = [0] * LT_d

    WORD_generation(SBOX_d, W_d) 

    E = ['' for i in range(4)]
    S = ['' for i in range(4)]

    for i in range(0, LT):
        TIndex = transposition_index_generation(TBOX_d, i)
        while(IndexArray_d[TIndex % N_d] != 0):
            TIndex = TIndex + 1
        TIndex = TIndex % N_d
        #write E[i] in encrypted file SE in position of TIndex
        E[i] = SE[TIndex]
        IndexArray_d[TIndex] = 1


    for i in range(0, LT - 1):
        for j in range(0, LT):
            #E[j] = binstr.b_xor(W[j], S[j])
            S[j] = binstr.b_xor(W[j],E[j])
        for j in range(0, LT):
            if(EvenParity(E[j]) == True):
                Rotate_Right(j, SBOX)
            else:
                Rotate_Left(j, SBOX)
                

            SBOX[2][j] = binstr.b_xor(SBOX[2][j], bin(SrtB[j])[2:].zfill(8))
        
        S = [str(x) for x in numpy.roll(S, 1)]
        Transpose(SBOX)

    for i in range(LT):
        SD.append(int(S[i],2))
        SrtB[i] = int(S[i],2)

    swap(TBOX, SBOX)

    return SD


if __name__ == '__main__':

            # take user input for key ( >= 16 Bytes )
            user_input_key = bytearray(raw_input("Enter key >=16 bytes: "))

#    with open('test_cases.txt', 'r') as f:
#        for line in f.read().split('\n'):
#            user_input_key = bytearray(line)

            if len(user_input_key) < 16:
                print "Key must be of length >= 16"
                exit(0)

            # Ky is the array of Bytes of user_input_key , each Byte represented in binary form as a string
            Ky = [bin(x)[2:].zfill(8) for x in user_input_key]

            # Intermediate output #1
            print 'Ky ( user input key )\nSize : ', len(Ky), '\n', Ky, '\n\n'

            # Generation of digest string from Ky
            digest_string_in_hex = hashlib.md5(user_input_key).hexdigest()
            digest_string = bytearray.fromhex(digest_string_in_hex)

            # Intermediate output #2
            print 'Digest String in hex\nSize : ', len(digest_string_in_hex), '\n', digest_string_in_hex, '\n'

            # D is the array of Bytes of the digest string generated, each Byte represented in binary form as a string
            D = [bin(x)[2:].zfill(8) for x in digest_string]

            # Intermediate output #2
            print 'D\nSize : ', len(D), '\n', D, '\n\n'

            # Intermediate output #3
            Eky1 = encryption_key_gen(Eky, Ky, D)
            print 'EKy ( generated from Ky and D ) \nSize : ', len(Eky1), '\n', Eky1, '\n\n'

            # Intermediate output #4
            SBOX_generation(SBOX, Eky1)
            print 'SBOX ( LT x LT ) ( LT = 4 )\n', SBOX, '\n\n'

            # Intermediate output #5
            TBOX_generation(TBOX, Eky1)
            print 'TBOX ( LT x LT ) ( LT = 4 )\n', TBOX, '\n\n'

            # Intermediate output #6
            WORD_generation(SBOX, W)
            print 'WORD ( 1 x LT ) ( LT = 4 )\n', W, '\n\n'

            # Intermediate output #7
            # TIndex1 = transposition_index_generation(TBOX, 3)
            # print 'TIndex ( 0 < TIndex < N ) ( N - size of secret file in Bytes ) \n', TIndex1, '\n\n'

            # Rotate_Right(1, SBOX)
            # print "SBOX after rotate right ",SBOX
            # Rotate_Left(1, SBOX)
            # print "SBOX after rotate left ",SBOX

            input_image = raw_input('Enter image path : ')
            image_file_name = re.search('.*/(.*)',input_image).group(1)


            f = numpy.array(Image.open(input_image))
            shape1 = f.shape
            f = f.reshape((1,shape1[0]*shape1[1]))
            S = [bin(x)[2:].zfill(8) for x in f[0]]

            N = len(S)

            #padding
            while(N % LT != 0):
                S.extend('00000000')
                N = N + 1

            print 'N = ',N
            IndexArray = [0] * N
            SrtB = [0] * LT

            # encrypted file
            SE = bytearray(N)

            #print 'It -1 \nSBOX\n{}\n{}\n{}\n{}\nTBOX\n{}\n{}\n{}\n{}\n'.format(SBOX[0],SBOX[1],SBOX[2],SBOX[3],TBOX[0],TBOX[1],TBOX[2],TBOX[3])
            for i in range(0,N,4):
                SE, SBOX, TBOX = Encrypt(S[i:i+4], SE, SBOX, TBOX, IndexArray, SrtB)
                #if i < 5:
                #    print 'It{}\nSBOX\n{}\n{}\n{}\n{}\nTBOX\n{}\n{}\n{}\n{}\n'.format(i,SBOX[0],SBOX[1],SBOX[2],SBOX[3],TBOX[0],TBOX[1],TBOX[2],TBOX[3])

            #SE = [bin(x)[2:].zfill(8) for x in SE]
            SE = numpy.array(SE).reshape(shape1)           
            scipy.misc.imsave(os.path.join(os.getcwd(),'encrypted_images/') + image_file_name, SE)
            

            
            #try using imageio

            ################ #decryption ################




'''
            f = numpy.array(Image.open('encrypted_image.bmp'))
            shape1 = f.shape
            f = f.reshape((1,shape1[0]*shape1[1]))
            SE = [bin(x)[2:].zfill(8) for x in f[0]]

            N = len(S)

            IndexArray = [0] * N
            SrtB = [0] * LT

            SD = bytearray(N)

            for i in range(0,N,4):
                SD = Decrypt(SE[i:i+4], SD, SBOX, TBOX, IndexArray, SrtB)

            SD = numpy.array(SD).reshape(shape1)
            scipy.misc.imsave('decrypted_image.bmp',SD)
'''


            #e_image_in_bits = str(''.join(SE))
            #e_image_in_base64 = base64.b64encode(e_image_in_bits)

            #encrypted_image = open('encrypted_image.bmp','wb')
            #encrypted_image.write(e_image_in_base64.decode('base64'))
            #encrypted_image.close()
            
            #encrypted_image = Image.open(io.BytesIO(SE))
            #encrypted_image.save(os.path.join(os.getcwd(),'encrypted_image.bmp'))


            
            
            
