
from utils.useful_functions import utf8_to_bytes, bytes_to_hex, chunk_bytes, rotate_left

# ρ-step rotation offsets (x = column, y = row)
RHO_OFFSETS = [
    [ 0,  1, 62, 28, 27],
    [36, 44,  6, 55, 20],
    [ 3, 10, 43, 25, 39],
    [41, 45, 15, 21,  8],
    [18,  2, 61, 56, 14],
]

# Correct Keccak-f[1600] round constants (24 rounds)
RC = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
]

MASK64 = (1 << 64) - 1


# ─────────────────────────────── Padding ────────────────────────────────
def pad10star1(msg: bytes, rate: int) -> bytes:
    rate_bytes = rate // 8
    padded = bytearray(msg)
    padded.append(0x06)                       # domain-separation bits + first 1
    while (len(padded) % rate_bytes) != rate_bytes - 1:
        padded.append(0x00)
    padded.append(0x80)                       # final 1 (MSB of last byte)
    return bytes(padded)


# ───────────────────────────── Lane helpers ─────────────────────────────
def bytes_to_lanes(block: bytes, w: int = 64) -> list[int]:
    step = w // 8
    return [int.from_bytes(block[i:i+step], 'little')
            for i in range(0, len(block), step)]


# ────────────────────────────── Sub-steps ───────────────────────────────
def theta(A):
    C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
    D = [(C[(x-1) % 5] ^ rotate_left(C[(x+1) % 5], 1, 64)) & MASK64
         for x in range(5)]
    for x in range(5):
        for y in range(5):
            A[x][y] ^= D[x]
    return A


def rho(A):
    for y in range(5):
        for x in range(5):
            A[x][y] = rotate_left(A[x][y], RHO_OFFSETS[y][x], 64) & MASK64
    return A


def pi(A):
    B = [[0]*5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            B[y][(2*x + 3*y) % 5] = A[x][y]
    return B


def chi(A):
    B = [[0]*5 for _ in range(5)]
    for y in range(5):
        for x in range(5):
            B[x][y] = (A[x][y] ^
                        ((~A[(x+1) % 5][y] & MASK64) & A[(x+2) % 5][y])) & MASK64
    return B


def iota(A, rnd):
    A[0][0] = (A[0][0] ^ RC[rnd]) & MASK64
    return A


# ─────────────────────────── Keccak-f permutation ───────────────────────
def keccak_f(state):
    for rnd in range(24):
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, rnd)
    return state


# ────────────────────────────── Sponge ──────────────────────────────────
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


def sha3_256(msg: str) -> str:
    rate, out_len = 1088, 256
    padded = pad10star1(utf8_to_bytes(msg), rate)
    state  = [[0]*5 for _ in range(5)]
    state  = absorb(state, padded, rate)
    digest = squeeze(state, rate, out_len)
    return bytes_to_hex(digest)

def sha3_512(msg: str) -> str:
    rate, out_len = 576, 512
    padded = pad10star1(utf8_to_bytes(msg), rate)
    state  = [[0]*5 for _ in range(5)]
    state  = absorb(state, padded, rate)
    digest = squeeze(state, rate, out_len)
    return bytes_to_hex(digest)

def sha3_224(msg: str) -> str:
    rate, out_len = 1152, 224
    padded = pad10star1(utf8_to_bytes(msg), rate)
    state  = [[0]*5 for _ in range(5)]
    state  = absorb(state, padded, rate)
    digest = squeeze(state, rate, out_len)
    return bytes_to_hex(digest)

def sha3_384(msg: str) -> str:
    rate, out_len = 832, 384
    padded = pad10star1(utf8_to_bytes(msg), rate)
    state  = [[0]*5 for _ in range(5)]
    state  = absorb(state, padded, rate)
    digest = squeeze(state, rate, out_len)
    return bytes_to_hex(digest)

