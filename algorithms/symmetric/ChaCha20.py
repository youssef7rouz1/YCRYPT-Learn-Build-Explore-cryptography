import struct
from typing import List
from utils.useful_functions import utf8_to_bytes, bytes_to_utf8, hex_to_bytes, bytes_to_hex

# Rotate-left for 32-bit words
def rotl32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

# One quarter-round of the ChaCha20 state
def quarter_round(a: int, b: int, c: int, d: int) -> List[int]:
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b, 7)
    return [a, b, c, d]

def u32_to_le_bytes(x: int) -> bytes:
    return struct.pack('<I', x)

# Initialize the 16-word ChaCha20 state (constant || key || counter || nonce)
def chacha20_init_state(key: bytes, counter: int, nonce: bytes) -> List[int]:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("Key must be 32 bytes and nonce 12 bytes")
    const = b"expand 32-byte k"
    state = [int.from_bytes(const[i:i+4], 'little') for i in range(0, 16, 4)]
    state += [int.from_bytes(key[i*4:(i+1)*4], 'little') for i in range(8)]
    state.append(counter & 0xFFFFFFFF)
    state += [int.from_bytes(nonce[i*4:(i+1)*4], 'little') for i in range(3)]
    return state

# Apply 20 rounds (10 column + 10 diagonal) of quarter-rounds
def chacha20_permute(state: List[int]) -> List[int]:
    w = state.copy()
    for _ in range(10):
        # columns
        w[0], w[4], w[8],  w[12] = quarter_round(w[0], w[4], w[8],  w[12])
        w[1], w[5], w[9],  w[13] = quarter_round(w[1], w[5], w[9],  w[13])
        w[2], w[6], w[10], w[14] = quarter_round(w[2], w[6], w[10], w[14])
        w[3], w[7], w[11], w[15] = quarter_round(w[3], w[7], w[11], w[15])
        # diagonals
        w[0], w[5],  w[10], w[15] = quarter_round(w[0], w[5],  w[10], w[15])
        w[1], w[6],  w[11], w[12] = quarter_round(w[1], w[6],  w[11], w[12])
        w[2], w[7],  w[8],  w[13] = quarter_round(w[2], w[7],  w[8],  w[13])
        w[3], w[4],  w[9],  w[14] = quarter_round(w[3], w[4],  w[9],  w[14])
    return w

# Generate a 64-byte keystream block
def chacha20_block(state: List[int]) -> bytes:
    w = chacha20_permute(state)
    out = bytearray()
    for i in range(16):
        word = (w[i] + state[i]) & 0xFFFFFFFF
        out += u32_to_le_bytes(word)
    return bytes(out)

# Encrypt or decrypt by XOR-ing keystream
def chacha20_encrypt(plaintext: str, key_str: str, nonce_str: str, initial_counter: int = 1) -> str:
    key   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    data  = utf8_to_bytes(plaintext)
    out   = bytearray()
    ctr   = initial_counter

    for offset in range(0, len(data), 64):
        ks = chacha20_block(chacha20_init_state(key, ctr, nonce))
        chunk = data[offset:offset+64]
        out.extend(b ^ ks[i] for i, b in enumerate(chunk))
        ctr += 1

    return bytes_to_hex(bytes(out))

def chacha20_decrypt(cipher_hex: str, key_str: str, nonce_str: str, initial_counter: int = 1) -> str:
    key   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    data  = hex_to_bytes(cipher_hex)
    out   = bytearray()
    ctr   = initial_counter

    for offset in range(0, len(data), 64):
        ks    = chacha20_block(chacha20_init_state(key, ctr, nonce))
        chunk = data[offset:offset+64]
        out.extend(b ^ ks[i] for i, b in enumerate(chunk))
        ctr += 1

    return bytes_to_utf8(bytes(out))

# Derive subkey for XChaCha20 using HChaCha20
def hchacha20_init_state(key: bytes, nonce16: bytes) -> List[int]:
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("Need 32-byte key and 16-byte nonce")
    const = b"expand 32-byte k"
    state = [int.from_bytes(const[i:i+4], 'little') for i in range(0, 16, 4)]
    state += [int.from_bytes(key[i*4:(i+1)*4], 'little') for i in range(8)]
    state += [int.from_bytes(nonce16[i*4:(i+1)*4], 'little') for i in range(4)]
    return state

def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    state = hchacha20_init_state(key, nonce16)
    perm  = chacha20_permute(state)
    words = perm[0:4] + perm[12:16]
    return b''.join(u32_to_le_bytes(w) for w in words)

# XChaCha20: derive subkey, then run ChaCha20-CTR
def xchacha20_encrypt(plaintext: str, key_str: str, nonce_str: str, initial_counter: int = 1) -> str:
    key_full = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce24  = utf8_to_bytes(nonce_str)[:24].ljust(24, b'\x00')
    pt       = utf8_to_bytes(plaintext)

    subkey   = hchacha20(key_full, nonce24[:16])
    nonce12  = b'\x00'*4 + nonce24[16:]
    out      = bytearray()
    ctr      = initial_counter

    for offset in range(0, len(pt), 64):
        ks = chacha20_block(chacha20_init_state(subkey, ctr, nonce12))
        chunk = pt[offset:offset+64]
        out.extend(b ^ ks[i] for i, b in enumerate(chunk))
        ctr += 1

    return bytes_to_hex(bytes(out))

def xchacha20_decrypt(cipher_hex: str, key_str: str, nonce_str: str, initial_counter: int = 1) -> str:
    key_full = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce24  = utf8_to_bytes(nonce_str)[:24].ljust(24, b'\x00')
    data     = hex_to_bytes(cipher_hex)

    subkey   = hchacha20(key_full, nonce24[:16])
    nonce12  = b'\x00'*4 + nonce24[16:]
    out      = bytearray()
    ctr      = initial_counter

    for offset in range(0, len(data), 64):
        ks = chacha20_block(chacha20_init_state(subkey, ctr, nonce12))
        chunk = data[offset:offset+64]
        out.extend(b ^ ks[i] for i, b in enumerate(chunk))
        ctr += 1

    return bytes_to_utf8(bytes(out))
