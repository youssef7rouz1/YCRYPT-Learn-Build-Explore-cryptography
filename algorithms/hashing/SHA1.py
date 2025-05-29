from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_hex,
    chunk_bytes,
    bytes_to_int,
    rotate_left,
)

# 1) Padding (length in bits appended big‑endian)
def sha1_pad(message: bytes) -> bytes:
    original_bit_len = len(message) * 8
    # append '1' bit (0x80), then zero bytes to reach 56 mod 64
    padded = message + b'\x80'
    pad_len = (56 - (len(padded) % 64)) % 64
    padded += b'\x00' * pad_len
    # append 64‑bit length BE
    padded += original_bit_len.to_bytes(8, 'big')
    return padded

# 2) Parsing blocks into 16 big‑endian words each
def sha1_parse_blocks(padded: bytes) -> list[list[int]]:
    if len(padded) % 64 != 0:
        raise ValueError("Padded length must be multiple of 64 bytes")
    blocks = []
    for block in chunk_bytes(padded, 64):
        words = [bytes_to_int(word, 'big') for word in chunk_bytes(block, 4)]
        blocks.append(words)
    return blocks

# 3) SHA‑1 f and K functions
def f(b, c, d, t):
    if t < 20:
        return (b & c) | (~b & d)
    if t < 40:
        return b ^ c ^ d
    if t < 60:
        return (b & c) | (b & d) | (c & d)
    return b ^ c ^ d

def K(t):
    if t < 20:
        return 0x5A827999
    if t < 40:
        return 0x6ED9EBA1
    if t < 60:
        return 0x8F1BBCDC
    return 0xCA62C1D6

# 4) Message schedule: extend 16→80 words
def message_schedule_expansion(block: list[int]) -> list[int]:
    W = block.copy()
    for t in range(16, 80):
        val = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
        W.append(rotate_left(val, 1, 32))
    return W

# 5) Compression of one block
def sha1_compress_block(state: tuple[int,int,int,int,int], block_words: list[int]) -> tuple[int,int,int,int,int]:
    A, B, C, D, E = state
    AA, BB, CC, DD, EE = A, B, C, D, E

    W = message_schedule_expansion(block_words)
    for t in range(80):
        temp = (
            rotate_left(A, 5, 32) +
            f(B, C, D, t) +
            E +
            K(t) +
            W[t]
        ) & 0xFFFFFFFF
        E = D
        D = C
        C = rotate_left(B, 30, 32)
        B = A
        A = temp

    # Feed‑forward
    return (
        (AA + A) & 0xFFFFFFFF,
        (BB + B) & 0xFFFFFFFF,
        (CC + C) & 0xFFFFFFFF,
        (DD + D) & 0xFFFFFFFF,
        (EE + E) & 0xFFFFFFFF,
    )

# 6) Initialization and finalization
def sha1_init_state() -> tuple[int,int,int,int,int]:
    return (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

def sha1_finalize(state: tuple[int,int,int,int,int]) -> bytes:
    H0, H1, H2, H3, H4 = state
    # output each H as 4‑byte big‑endian
    return (
        H0.to_bytes(4, 'big') +
        H1.to_bytes(4, 'big') +
        H2.to_bytes(4, 'big') +
        H3.to_bytes(4, 'big') +
        H4.to_bytes(4, 'big')
    )

# 7) High‑level SHA‑1 API
def sha1(message: str) -> str:
    """
    Compute SHA-1 of the input UTF-8 string and return uppercase hex digest.
    """
    msg_bytes = utf8_to_bytes(message)
    padded = sha1_pad(msg_bytes)
    blocks = sha1_parse_blocks(padded)

    state = sha1_init_state()
    for block in blocks:
        state = sha1_compress_block(state, block)

    digest = sha1_finalize(state)
    return bytes_to_hex(digest)
