import math
from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_hex,
    chunk_bytes,
    bytes_to_int,
    rotate_left,
)

# 1) Precompute the 64 MD5 constants
T = [int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]

# Padding
def md5_pad(message: bytes) -> bytes:
    original_bit_len = len(message) * 8
    padded = message + b'\x80'
    pad_len = (56 - (len(padded) % 64)) % 64
    padded += b'\x00' * pad_len
    padded += original_bit_len.to_bytes(8, 'little')
    return padded

def md5_parse_blocks(padded: bytes) -> list[list[int]]:
    return [
        [bytes_to_int(w, 'little') for w in chunk_bytes(block, 4)]
        for block in chunk_bytes(padded, 64)
    ]



def F(x, y, z): return (x & y) | (~x & z)
def G(x, y, z): return (x & z) | (y & ~z)
def H(x, y, z): return x ^ y ^ z
def I(x, y, z): return y ^ (x | ~z)




# Compression
def md5_compress_block(state, X):
    A, B, C, D = state
    AA, BB, CC, DD = A, B, C, D

    # Round 1
    s1 = [7, 12, 17, 22]
    for i in range(16):
        a = (A + F(B, C, D) + X[i] + T[i]) & 0xFFFFFFFF
        a = rotate_left(a, s1[i % 4] , 32)
        a = (a + B) & 0xFFFFFFFF
        A, B, C, D = D, a, B, C

    # Round 2
    s2 = [5, 9, 14, 20]
    for i in range(16):
        k = (1 + 5 * i) % 16
        a = (A + G(B, C, D) + X[k] + T[16 + i]) & 0xFFFFFFFF
        a = rotate_left(a, s2[i % 4] , 32)
        a = (a + B) & 0xFFFFFFFF
        A, B, C, D = D, a, B, C

    # Round 3
    s3 = [4, 11, 16, 23]
    for i in range(16):
        k = (5 + 3 * i) % 16
        a = (A + H(B, C, D) + X[k] + T[32 + i]) & 0xFFFFFFFF
        a = rotate_left(a, s3[i % 4] , 32)
        a = (a + B) & 0xFFFFFFFF
        A, B, C, D = D, a, B, C

    # Round 4
    s4 = [6, 10, 15, 21]
    for i in range(16):
        k = (7 * i) % 16
        a = (A + I(B, C, D) + X[k] + T[48 + i]) & 0xFFFFFFFF
        a = rotate_left(a, s4[i % 4] , 32)
        a = (a + B) & 0xFFFFFFFF
        A, B, C, D = D, a, B, C

    # Feed-forward
    return (
        (A + AA) & 0xFFFFFFFF,
        (B + BB) & 0xFFFFFFFF,
        (C + CC) & 0xFFFFFFFF,
        (D + DD) & 0xFFFFFFFF,
    )

def md5_init_state():
    return (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

def md5_finalize(state):
    A, B, C, D = state
    return (
        A.to_bytes(4, 'little') +
        B.to_bytes(4, 'little') +
        C.to_bytes(4, 'little') +
        D.to_bytes(4, 'little')
    )

def md5(message: str) -> str:
    msg_bytes = utf8_to_bytes(message)
    padded = md5_pad(msg_bytes)
    blocks = md5_parse_blocks(padded)
    state = md5_init_state()
    for X in blocks:
        state = md5_compress_block(state, X)
    digest = md5_finalize(state)
    return bytes_to_hex(digest)


if __name__=="__main__":
    msg="hello"
    print("hash=" , md5(msg))
