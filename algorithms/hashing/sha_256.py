import math
from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_hex,
    chunk_bytes,
    bytes_to_int,
    
    rotate_right,
    
)

def generate_sha256_constants() -> list[int]:
    """Generate the SHA-256 K constants from the first 64 primes."""
    # 1) Generate first 64 primes via trial division
    primes = []
    num = 2
    while len(primes) < 64:
        is_prime = True
        for p in primes:
            if p * p > num:
                break
            if num % p == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(num)
        num += 1

    # 2) Compute K constants: floor(frac(cuberoot(prime)) * 2^32)
    constants = []
    for p in primes:
        frac = math.modf(p ** (1/3))[0]
        if frac < 0:
            frac += 1.0
        constants.append(int(frac * (1 << 32)) & 0xFFFFFFFF)
    return constants

# Precompute K[0..63]
K = generate_sha256_constants()

# 1) Padding
def sha256_pad(message: bytes) -> bytes:
    L = len(message) * 8
    padded = message + b'\x80'
    pad_len = (56 - len(padded) % 64) % 64
    padded += b'\x00' * pad_len
    padded += L.to_bytes(8, 'big')
    return padded

# 2) Parse into 512-bit blocks of 16 big-endian words
def sha256_parse_blocks(padded: bytes) -> list[list[int]]:
    if len(padded) % 64:
        raise ValueError("Padded message not multiple of 64 bytes")
    blocks = []
    for block in chunk_bytes(padded, 64):
        blocks.append([bytes_to_int(w, 'big') for w in chunk_bytes(block, 4)])
    return blocks

# 3) Bitwise functions
# 3) Bitwise functions (corrected)
def ch(x, y, z) -> int:
    return (x & y) ^ (~x & z)

def maj(x, y, z) -> int:
    return (x & y) ^ (x & z) ^ (y & z)

def big_sigma0(x: int) -> int:
    return (
        rotate_right(x, 2, 32)
        ^ rotate_right(x, 13, 32)
        ^ rotate_right(x, 22, 32)
    ) & 0xFFFFFFFF

def big_sigma1(x: int) -> int:
    return (
        rotate_right(x, 6, 32)
        ^ rotate_right(x, 11, 32)
        ^ rotate_right(x, 25, 32)
    ) & 0xFFFFFFFF

def small_sigma0(x: int) -> int:
    # σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
    return (
        rotate_right(x, 7, 32)
        ^ rotate_right(x, 18, 32)
        ^ (x >> 3)
    ) & 0xFFFFFFFF

def small_sigma1(x: int) -> int:
    # σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
    return (
        rotate_right(x, 17, 32)
        ^ rotate_right(x, 19, 32)
        ^ (x >> 10)
    ) & 0xFFFFFFFF


# 4) Message schedule expansion
def message_schedule_expansion(block: list[int]) -> list[int]:
    W = block.copy()
    for t in range(16, 64):
        s0 = small_sigma0(W[t-15])
        s1 = small_sigma1(W[t-2])
        W.append((W[t-16] + s0 + W[t-7] + s1) & 0xFFFFFFFF)
    return W

# 5) Compression of one block
def sha256_compress_block(state: tuple[int,int,int,int,int,int,int,int], block_words: list[int]) -> tuple[int,int,int,int,int,int,int,int]:
    a, b, c, d, e, f, g, h = state
    W = message_schedule_expansion(block_words)
    for t in range(64):
        T1 = (h + big_sigma1(e) + ch(e,f,g) + K[t] + W[t]) & 0xFFFFFFFF
        T2 = (big_sigma0(a) + maj(a,b,c)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF
    return (
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
        (state[5] + f) & 0xFFFFFFFF,
        (state[6] + g) & 0xFFFFFFFF,
        (state[7] + h) & 0xFFFFFFFF,
    )

# 6) Initial and final state
def sha256_init_state() -> tuple[int,int,int,int,int,int,int,int]:
    return (
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    )

def sha256_finalize(state: tuple[int,int,int,int,int,int,int,int]) -> bytes:
    return b''.join(h.to_bytes(4, 'big') for h in state)

# 7) High-level SHA-256 API
def sha256(message: str) -> str:
    msg_bytes = utf8_to_bytes(message)
    padded = sha256_pad(msg_bytes)
    blocks = sha256_parse_blocks(padded)
    state = sha256_init_state()
    for block in blocks:
        state = sha256_compress_block(state, block)
    return bytes_to_hex(sha256_finalize(state))

# Quick test
if __name__ == "__main__":
    print("SHA-256('hello') =", sha256("hello"))  # Expect: 2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824