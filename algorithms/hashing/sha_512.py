import math
from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_hex,
    chunk_bytes,
    bytes_to_int,
    rotate_right,
)

# ————————————————————————————————————————————————
# 1) Hard-coded SHA-512 constants (first 80 cube‐root fractions)
K512 = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC, 0x3956C25BF348B538, 0x59F111F1B605D019,
    0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242,
    0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
    0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65, 0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
    0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC,
    0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6,
    0x92722C851482353B, 0xA2BFE8A14CF10364, 0xA81A664BBC423001,
    0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
    0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC,
    0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915,
    0xC67178F2E372532B, 0xCA273ECEEA26619C, 0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA,
    0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
]

# 2) Padding for SHA-512
def sha512_pad(message: bytes) -> bytes:
    L = len(message) * 8
    padded = message + b'\x80'
    pad_len = (112 - len(padded) % 128) % 128
    padded += b'\x00' * pad_len
    # 128-bit big-endian length
    padded += L.to_bytes(16, 'big')
    return padded

# 3) Parse into 1024-bit blocks of 16 64-bit words
def sha512_parse_blocks(padded: bytes) -> list[list[int]]:
    if len(padded) % 128:
        raise ValueError("Padded message not multiple of 128 bytes")
    blocks = []
    for block in chunk_bytes(padded, 128):
        blocks.append([bytes_to_int(w, 'big') for w in chunk_bytes(block, 8)])
    return blocks

# 4) SHA-512 bitwise helpers
def ch(x, y, z): return (x & y) ^ (~x & z)
def maj(x, y, z): return (x & y) ^ (x & z) ^ (y & z)
def big_sigma0(x):
    return (
        rotate_right(x, 28, 64) ^
        rotate_right(x, 34, 64) ^
        rotate_right(x, 39, 64)
    ) & 0xFFFFFFFFFFFFFFFF
def big_sigma1(x):
    return (
        rotate_right(x, 14, 64) ^
        rotate_right(x, 18, 64) ^
        rotate_right(x, 41, 64)
    ) & 0xFFFFFFFFFFFFFFFF
def small_sigma0(x):
    return (
        rotate_right(x, 1, 64) ^
        rotate_right(x, 8, 64) ^
        (x >> 7)
    ) & 0xFFFFFFFFFFFFFFFF
def small_sigma1(x):
    return (
        rotate_right(x, 19, 64) ^
        rotate_right(x, 61, 64) ^
        (x >> 6)
    ) & 0xFFFFFFFFFFFFFFFF

# 5) Message schedule expansion
def message_schedule_expansion_512(block):
    W = block.copy()
    for t in range(16, 80):
        s0 = small_sigma0(W[t-15])
        s1 = small_sigma1(W[t-2])
        W.append((W[t-16] + s0 + W[t-7] + s1) & 0xFFFFFFFFFFFFFFFF)
    return W

# 6) Compression of one block
def sha512_compress_block(state, block_words):
    a,b,c,d,e,f,g,h = state
    W = message_schedule_expansion_512(block_words)
    for t in range(80):
        T1 = (h + big_sigma1(e) + ch(e,f,g) + K512[t] + W[t]) & 0xFFFFFFFFFFFFFFFF
        T2 = (big_sigma0(a) + maj(a,b,c)) & 0xFFFFFFFFFFFFFFFF
        h=g; g=f; f=e; e=(d+T1)&0xFFFFFFFFFFFFFFFF
        d=c; c=b; b=a; a=(T1+T2)&0xFFFFFFFFFFFFFFFF
    return (
        (state[0]+a)&0xFFFFFFFFFFFFFFFF,
        (state[1]+b)&0xFFFFFFFFFFFFFFFF,
        (state[2]+c)&0xFFFFFFFFFFFFFFFF,
        (state[3]+d)&0xFFFFFFFFFFFFFFFF,
        (state[4]+e)&0xFFFFFFFFFFFFFFFF,
        (state[5]+f)&0xFFFFFFFFFFFFFFFF,
        (state[6]+g)&0xFFFFFFFFFFFFFFFF,
        (state[7]+h)&0xFFFFFFFFFFFFFFFF,
    )

# 7) Initial and final state
def sha512_init_state():
    return (
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    )

def sha512_finalize(state):
    return b''.join(h.to_bytes(8, 'big') for h in state)

# 8) High-level SHA-512 API
def sha512(message: str) -> str:
    msg_bytes = utf8_to_bytes(message)
    padded   = sha512_pad(msg_bytes)
    blocks   = sha512_parse_blocks(padded)
    state    = sha512_init_state()
    for blk in blocks:
        state = sha512_compress_block(state, blk)
    return bytes_to_hex(sha512_finalize(state))

# Quick sanity check
if __name__ == "__main__":
    import hashlib
    out = sha512("hello")
    print("SHA-512('hello') =", out)
    print(" matches hashlib? ", out == hashlib.sha512(b"hello").hexdigest().upper())