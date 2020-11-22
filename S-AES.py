"""
Simplified AES algorithm code in python
    By: Yash Sharma
    Date: 22/11/2020
    Roll Number: 1810110283
"""

# ------------------- START OF POLYNOMIAL ARITHMETIC ------------------- #

# divide polynomial to get remainder
def poly_divmod(num, den):
    # make their degrees equal by pre appending 0s
    if len(num) >= len(den):
        shiftlen = len(num) - len(den)
        den = [0] * shiftlen + den
    else:
        return [0], num

    quot = []

    # convert to float as we can get decimal values as well
    divisor = float(den[-1])

    # one by one divide each of the values
    for i in range(shiftlen + 1):
        mult = num[-1] / divisor
        quot = [mult] + quot

        if mult != 0:
            d = [mult * u for u in den]
            num = [u - v for u, v in zip(num, d)]
        num.pop()
        den.pop(0)

    return quot, num

# retruns the final GF4 answer
def GF4MultiyplyInner(num):
    den = [1,1,0,0,1]
    q, r = poly_divmod(num, den)
    for i in range(len(r)):
        r[i] = int(r[i])
        if r[i] == -1:
            r[i] = 1
        elif r[i] not in {0,1}:
            r[i] = 0
    multiplier = 1
    answer = 0
    for i in r:
        answer += i*multiplier
        multiplier*=2
    return answer

# multiply 2 polynomials 
def multiply(A, B): 
    m = len(A)
    n = len(B)
    prod = [0] * (m + n - 1) 
    for i in range(m): 
        for j in range(n): 
            prod[i + j] += A[i] * B[j]
  
    return prod 

# final function to be used in algorithm
def GF4Multiyply(a,b):
    a = [int(i) for i in bin(a)[2:]]
    b = [int(i) for i in bin(b)[2:]]
    a = a[::-1]
    b = b[::-1]
    k = multiply(a,b)
    return GF4MultiyplyInner(k)

# ------------------- END OF POLYNOMIAL ARITHMETIC ------------------- #


# ------------------- VARIABLES ------------------- #
# round counts
RC1, RC2 = 0b10000000, 0b00110000

# variables
plaintext = 0b1101011100101000
key = 0b0100101011110101
ciphertext = 0b0010010011101100

# sbox table
sBox = [
    0x9, 0x4, 0xa, 0xb,
    0xd, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xc, 0xe, 0xf, 0x7
]

# inverse sbox table
inverseSBox = [
    0xa, 0x5, 0x9, 0xb,
    0x1, 0x7, 0x8, 0xf,
    0x6, 0x0, 0x2, 0x3,
    0xc, 0x4, 0xd, 0xe
]

# ------------------- END OF VARIABLES ------------------- #



# ------------------- KEY EXPANSION ------------------- #
# sub nibble function
def subNib(wTuple):
    wRight = wTuple[0]
    wLeft = wTuple[1]
    return sBox[wRight]+(sBox[wLeft] << 4)

# rotation of nibble
def rotNib(w):
    wLeft = w & 0x0f
    wRight = w >> 4
    return (wRight, wLeft)


# key expansion
w0 = key >> 8
w1 = key & 0x00ff
w2 = w0 ^ RC1 ^ subNib(rotNib(w1))
w3 = w2 ^ w1
w4 = w2 ^ RC2 ^ subNib(rotNib(w3))
w5 = w4 ^ w3

# expanded keys
key0 = w1 + (w0 << 8)
key1 = w3 + (w2 << 8)
key2 = w5 + (w4 << 8)

# ------------------- END OF KEY EXPANSION ------------------- #



# ------------------- FUNTIONS TO BE USED ------------------- #

def nibbleSubstitution(n):
    return [sBox[n >> 12], sBox[(n >> 8) & 0xf], sBox[(n >> 4) & 0xf], sBox[n & 0xf]]

def inverseNibbleSubstitution(n):
    return [inverseSBox[n >> 12], inverseSBox[(n >> 8) & 0xf], inverseSBox[(n >> 4) & 0xf], inverseSBox[n & 0xf]]

# dividing of a binary number of 16 bits to 4 4 bit sub parts
def vector(x):
    return [x >> 12, (x >> 8) & 0xf, (x >> 4) & 0xf, x & 0xf]

# return a number formed by 4 sub parts of a binary number
def vectorInt(x):
    return (x[0] << 12) + (x[1] << 8) + (x[2] << 4) + x[3]


def encryption(plainText):
    # round 0 key
    n = plainText ^ key0
    # round 1
    ar = nibbleSubstitution(n)
    # round 1 shift
    ar[1], ar[3] = ar[3], ar[1]
    # mix column
    k = [ar[0] ^ GF4Multiyply(4, ar[2]), ar[1] ^ GF4Multiyply(4, ar[3]),
         ar[2] ^ GF4Multiyply(4, ar[0]), ar[3] ^ GF4Multiyply(4, ar[1])]
    k[1], k[2] = k[2], k[1]
    # round 1 key
    n2 = vector(key1)
    for i in range(len(k)):
        k[i] ^= n2[i]
    # final round
    # nibble substitution
    nbSub = nibbleSubstitution(vectorInt(k))
    nbSub[1], nbSub[3] = nbSub[3], nbSub[1]
    # round 2 key
    n3 = vector(key2)
    for i in range(len(nbSub)):
        nbSub[i] ^= n3[i]
    # cipher text
    return vectorInt(nbSub)


def decryption(cipherText):
    # round 2 key
    ar = vector(cipherText ^ key2)
    # inverse shift row
    ar[1], ar[3] = ar[3], ar[1]
    ar = inverseNibbleSubstitution(vectorInt(ar))
    # round 1 key
    n = vector(key1)
    for i in range(len(ar)):
        ar[i] ^= n[i]
    # inverse Mix column
    ar[1],ar[2]=ar[2],ar[1]
    k = [GF4Multiyply(9, ar[0]) ^ GF4Multiyply(2, ar[2]), GF4Multiyply(9, ar[1]) ^ GF4Multiyply(2, ar[3]),
         GF4Multiyply(9, ar[2]) ^ GF4Multiyply(2, ar[0]), GF4Multiyply(9, ar[3]) ^ GF4Multiyply(2, ar[1])]
    # inverse shift row
    k[1], k[3] = k[3], k[1]
    # inverse nibble sub
    k = inverseNibbleSubstitution(vectorInt(k))
    # round key 0
    n1 = vector(key0)
    for i in range(len(k)):
        k[i] ^= n1[i]
    return vectorInt(k)

# ------------------- END OF FUNTIONS TO BE USED ------------------- #


# ------------------- MAIN FUNCTION ------------------- #

# check if our algorithm works or not
if plaintext == decryption(encryption(plaintext)):
    print('Woah! The algorithm works just fine.')
else:
    print('Uh Oh! Some error occured.')

# ------------------- END OF MAIN FUNCTION ------------------- #

