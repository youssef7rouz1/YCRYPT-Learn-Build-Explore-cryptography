import math
from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_hex,
    chunk_bytes,
    bytes_to_int,
    rotate_left,
)

# Precompute MD5 constants
T = [int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]

def md5_pad(message: bytes) -> bytes:
    """
    Pad the message to a multiple of 64 bytes:
    - Append 0x80
    - Add zeros until length ≡ 56 mod 64
    - Append original length as 64-bit little-endian
    """
    bit_len = len(message) * 8
    padded = message + b'\x80'
    pad_len = (56 - len(padded) % 64) % 64
    return padded + b'\x00' * pad_len + bit_len.to_bytes(8, 'little')

def md5_parse_blocks(padded: bytes) -> list[list[int]]:
    """
    Split the padded message into 16-word (512-bit) blocks.
    Each word is a little-endian 32-bit integer.
    """
    return [
        [bytes_to_int(w, 'little') for w in chunk_bytes(block, 4)]
        for block in chunk_bytes(padded, 64)
    ]

# Basic MD5 functions
def F(x, y, z): return (x & y) | (~x & z)
def G(x, y, z): return (x & z) | (y & ~z)
def H(x, y, z): return x ^ y ^ z
def I(x, y, z): return y ^ (x | ~z)

def md5_compress_block(state, X):
    """
    Process one 512-bit block, updating the state (A, B, C, D).
    """
    A, B, C, D = state
    AA, BB, CC, DD = A, B, C, D

    # Round 1
    s1 = [7, 12, 17, 22]
    for i in range(16):
        A = (A + F(B, C, D) + X[i] + T[i]) & 0xFFFFFFFF
        A = rotate_left(A, s1[i % 4], 32)
        A = (A + B) & 0xFFFFFFFF
        A, B, C, D = D, A, B, C

    # Round 2
    s2 = [5, 9, 14, 20]
    for i in range(16):
        k = (1 + 5 * i) % 16
        A = (A + G(B, C, D) + X[k] + T[16 + i]) & 0xFFFFFFFF
        A = rotate_left(A, s2[i % 4], 32)
        A = (A + B) & 0xFFFFFFFF
        A, B, C, D = D, A, B, C

    # Round 3
    s3 = [4, 11, 16, 23]
    for i in range(16):
        k = (5 + 3 * i) % 16
        A = (A + H(B, C, D) + X[k] + T[32 + i]) & 0xFFFFFFFF
        A = rotate_left(A, s3[i % 4], 32)
        A = (A + B) & 0xFFFFFFFF
        A, B, C, D = D, A, B, C

    # Round 4
    s4 = [6, 10, 15, 21]
    for i in range(16):
        k = (7 * i) % 16
        A = (A + I(B, C, D) + X[k] + T[48 + i]) & 0xFFFFFFFF
        A = rotate_left(A, s4[i % 4], 32)
        A = (A + B) & 0xFFFFFFFF
        A, B, C, D = D, A, B, C

    # Add this block's result to the running state
    return (
        (A + AA) & 0xFFFFFFFF,
        (B + BB) & 0xFFFFFFFF,
        (C + CC) & 0xFFFFFFFF,
        (D + DD) & 0xFFFFFFFF,
    )

def md5_init_state():
    """Initial MD5 state (A, B, C, D)."""
    return (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

def md5_finalize(state):
    """Produce the final 16-byte digest from state."""
    A, B, C, D = state
    return (
        A.to_bytes(4, 'little') +
        B.to_bytes(4, 'little') +
        C.to_bytes(4, 'little') +
        D.to_bytes(4, 'little')
    )

def md5(message: str) -> str:
    """
    Compute MD5 hash of a UTF-8 string.
    Returns the hex digest (uppercase).
    """
    data = utf8_to_bytes(message)
    padded = md5_pad(data)
    blocks = md5_parse_blocks(padded)
    state = md5_init_state()
    for blk in blocks:
        state = md5_compress_block(state, blk)
    digest = md5_finalize(state)
    return bytes_to_hex(digest)
