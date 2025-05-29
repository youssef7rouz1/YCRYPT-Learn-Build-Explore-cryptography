import math
from utils.useful_functions import utf8_to_bytes, bytes_to_hex, chunk_bytes, rotate_left

RHO_OFFSETS = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
]

RC = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x000000000000008B,
    0x0000000000008089, 0x0000000000008003,
    0x0000000000008002, 0x0000000000000080,
    0x000000000000800A, 0x000000000000008A,
    0x0000000000008081, 0x8000000000008009,
    0x8000000000000001, 0x8000000080008080,
]

MASK64 = (1 << 64) - 1
def rotate_right(v: int, n: int, width: int = 64) -> int:
    n %= width
    return ((v >> n) | (v << (width - n))) & ((1 << width) - 1)


# pad10*1  ------------------------------------------------------------
def pad10star1(msg: bytes, rate: int) -> bytes:
    rate_bytes = rate // 8
    padded = bytearray(msg)
    padded.append(0x06)                          # 2-bit domain suffix + first ‘1’

    while (len(padded) % rate_bytes) != rate_bytes - 1:
        padded.append(0x00)                      # zero-pad

    padded.append(0x80)                          # final ‘1’ (MSB of last byte)
    return bytes(padded)


# helpers --------------------------------------------------------------
def bytes_to_lanes(block: bytes, w: int = 64) -> list[int]:
    step = w // 8
    return [int.from_bytes(block[i:i+step], 'little') for i in range(0, len(block), step)]


# ρ ───────────────────────────────────────────────
def rho(A):
    for x in range(5):
        for y in range(5):
            A[x][y] = rotate_left(A[x][y], RHO_OFFSETS[y][x], 64) & MASK64
    return A

# π ───────────────────────────────────────────────
def pi(A):
    B = [[0]*5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            B[x][y] = A[(x + 3*y) % 5][x] & MASK64
    return B

# θ ───────────────────────────────────────────────
def theta(A):
    C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
    D = [(C[(x-1) % 5] ^ rotate_left(C[(x+1) % 5], 1, 64)) & MASK64
         for x in range(5)]
    for x in range(5):
        for y in range(5):
            A[x][y] ^= D[x]
    return A


def chi(A):
    B = [[0]*5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            B[x][y] = (A[x][y] ^ ((~A[(x+1) % 5][y] & MASK64) & A[(x+2) % 5][y])) & MASK64
    return B


def iota(A, rnd):
    A[0][0] = (A[0][0] ^ RC[rnd]) & MASK64
    return A


# Keccak-f -------------------------------------------------------------
def keccak_f(state):
    for rnd in range(24):
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, rnd)
    return state


# sponge ---------------------------------------------------------------
def absorb(state, padded: bytes, rate: int):
    rate_bytes = rate // 8
    for block in chunk_bytes(padded, rate_bytes):
        for i, lane in enumerate(bytes_to_lanes(block)):
            x, y = i % 5, i // 5
            state[x][y] ^= lane
        state = keccak_f(state)
    return state


def squeeze(state, rate: int, out_len: int) -> bytes:
    rate_bytes = rate // 8
    output = b''
    while len(output) < out_len // 8:
        chunk = b''.join(state[i % 5][i // 5].to_bytes(8, 'little')
                         for i in range(rate_bytes // 8))
        output += chunk
        if len(output) < out_len // 8:
            state = keccak_f(state)
    return output[: out_len // 8]


# public API -----------------------------------------------------------
def sha3_256(msg: str) -> str:
    rate, out_len = 1088, 256
    padded = pad10star1(utf8_to_bytes(msg), rate)
    state  = [[0]*5 for _ in range(5)]
    state  = absorb(state, padded, rate)
    digest = squeeze(state, rate, out_len)
    return bytes_to_hex(digest)


# quick check ----------------------------------------------------------
if __name__ == "__main__":
    import hashlib
    m = "hello"
    mine = sha3_256(m)
    ref  = hashlib.sha3_256(m.encode()).hexdigest().upper()
    print(" mine:", mine)
    print("  ref:", ref)
    print("match:", mine == ref)
