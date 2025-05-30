from utils.useful_functions import (
    utf8_to_bytes, bytes_to_utf8, hex_to_utf8, utf8_to_hex,
    chunk_bytes, bytes_to_hex, bytes_to_int, rotate_left
)

def md4_pad(message: bytes) -> bytes:
    padded = message + b'\x80'
    pad_len = (56 - len(padded) % 64) % 64
    padded += b'\x00' * pad_len
    bit_len = len(message) * 8
    return padded + bit_len.to_bytes(8, 'little')

def md4_parse_blocks(padded: bytes) -> list[list[int]]:
    if len(padded) % 64 != 0:
        raise ValueError("Invalid padded length")
    blocks = []
    for blk in chunk_bytes(padded, 64):
        words = [bytes_to_int(w, 'little') for w in chunk_bytes(blk, 4)]
        blocks.append(words)
    return blocks

def F(x: int, y: int, z: int) -> int:
    return (x & y) | (~x & z)

def G(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)

def H(x: int, y: int, z: int) -> int:
    return x ^ y ^ z

def rotl32(x: int, s: int) -> int:
    return rotate_left(x, s, 32)

def md4_round1(a, b, c, d, X):
    s = [3, 7, 11, 19]
    for i in range(16):
        a = rotl32((a + F(b, c, d) + X[i]) & 0xFFFFFFFF, s[i % 4])
        a, b, c, d = d, a, b, c
    return a, b, c, d

def md4_round2(a, b, c, d, X):
    K = 0x5A827999
    order = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
    s = [3, 5, 9, 13]
    for i in range(16):
        k = order[i]
        a = rotl32((a + G(b, c, d) + X[k] + K) & 0xFFFFFFFF, s[i % 4])
        a, b, c, d = d, a, b, c
    return a, b, c, d

def md4_round3(a, b, c, d, X):
    K = 0x6ED9EBA1
    order = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
    s = [3, 9, 11, 15]
    for i in range(16):
        k = order[i]
        a = rotl32((a + H(b, c, d) + X[k] + K) & 0xFFFFFFFF, s[i % 4])
        a, b, c, d = d, a, b, c
    return a, b, c, d

def md4_compress_block(state: tuple[int,int,int,int], X: list[int]) -> tuple[int,int,int,int]:
    A, B, C, D = state
    AA, BB, CC, DD = A, B, C, D
    A, B, C, D = md4_round1(A, B, C, D, X)
    A, B, C, D = md4_round2(A, B, C, D, X)
    A, B, C, D = md4_round3(A, B, C, D, X)
    return ((A + AA) & 0xFFFFFFFF,
            (B + BB) & 0xFFFFFFFF,
            (C + CC) & 0xFFFFFFFF,
            (D + DD) & 0xFFFFFFFF)

def md4_init_state() -> tuple[int,int,int,int]:
    return (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

def md4_finalize(state: tuple[int,int,int,int]) -> bytes:
    A, B, C, D = state
    return b''.join(w.to_bytes(4, 'little') for w in (A, B, C, D))

def md4(message: str) -> str:
    m = utf8_to_bytes(message)
    padded = md4_pad(m)
    blocks = md4_parse_blocks(padded)
    state = md4_init_state()
    for blk in blocks:
        state = md4_compress_block(state, blk)
    return bytes_to_hex(md4_finalize(state))
