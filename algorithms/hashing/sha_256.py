import math
from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_hex,
    chunk_bytes,
    bytes_to_int,
    rotate_right,
)

def _compute_constants() -> list[int]:
    """Build the 64 SHA-256 round constants from prime cube roots."""
    primes = []
    n = 2
    while len(primes) < 64:
        if all(n % p for p in primes if p * p <= n):
            primes.append(n)
        n += 1

    constants = []
    for p in primes:
        frac = math.modf(p ** (1/3))[0]
        constants.append(int(frac * (1 << 32)) & 0xFFFFFFFF)
    return constants

K = _compute_constants()

def _pad(message: bytes) -> bytes:
    """Append the '1' bit, zeros, and message length to fit 512-bit blocks."""
    bit_len = len(message) * 8
    padded = message + b'\x80'
    pad_len = (56 - len(padded) % 64) % 64
    return padded + b'\x00' * pad_len + bit_len.to_bytes(8, 'big')

def _blocks(padded: bytes) -> list[list[int]]:
    """Split into 16-word blocks (big-endian)."""
    if len(padded) % 64:
        raise ValueError("Invalid padding length")
    out = []
    for chunk in chunk_bytes(padded, 64):
        words = [bytes_to_int(w, 'big') for w in chunk_bytes(chunk, 4)]
        out.append(words)
    return out

def _ch(x, y, z): return (x & y) ^ (~x & z)
def _maj(x, y, z): return (x & y) ^ (x & z) ^ (y & z)

def _big0(x: int) -> int:
    return (
        rotate_right(x, 2, 32)
        ^ rotate_right(x, 13, 32)
        ^ rotate_right(x, 22, 32)
    ) & 0xFFFFFFFF

def _big1(x: int) -> int:
    return (
        rotate_right(x, 6, 32)
        ^ rotate_right(x, 11, 32)
        ^ rotate_right(x, 25, 32)
    ) & 0xFFFFFFFF

def _small0(x: int) -> int:
    return (
        rotate_right(x, 7, 32)
        ^ rotate_right(x, 18, 32)
        ^ (x >> 3)
    ) & 0xFFFFFFFF

def _small1(x: int) -> int:
    return (
        rotate_right(x, 17, 32)
        ^ rotate_right(x, 19, 32)
        ^ (x >> 10)
    ) & 0xFFFFFFFF

def _expand(block: list[int]) -> list[int]:
    """Extend 16-word block to 64 words."""
    W = block.copy()
    for t in range(16, 64):
        s0 = _small0(W[t - 15])
        s1 = _small1(W[t - 2])
        W.append((W[t - 16] + s0 + W[t - 7] + s1) & 0xFFFFFFFF)
    return W

def _compress(state: tuple[int,int,int,int,int,int,int,int], block: list[int]) -> tuple[int,int,int,int,int,int,int,int]:
    """Process one 512-bit block."""
    a, b, c, d, e, f, g, h = state
    W = _expand(block)

    for t in range(64):
        T1 = (h + _big1(e) + _ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
        T2 = (_big0(a) + _maj(a, b, c)) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + T1) & 0xFFFFFFFF, c, b, a, (T1 + T2) & 0xFFFFFFFF

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

def _initial_state() -> tuple[int,int,int,int,int,int,int,int]:
    return (
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    )

def _finalize(state: tuple[int,int,int,int,int,int,int,int]) -> bytes:
    return b''.join(h.to_bytes(4, 'big') for h in state)

def sha256(message: str) -> str:
    """
    Compute SHA-256 hash of a string.
    Returns uppercase hex digest.
    """
    data = utf8_to_bytes(message)
    padded = _pad(data)
    blocks = _blocks(padded)

    state = _initial_state()
    for blk in blocks:
        state = _compress(state, blk)

    return bytes_to_hex(_finalize(state))
