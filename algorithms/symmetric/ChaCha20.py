import struct
from typing import List
from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_utf8,
    hex_to_bytes,
    bytes_to_hex,
)

# ─── Core primitives ──────────────────────────────────────────────────────────

def rotl32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def quarter_round(a: int, b: int, c: int, d: int) -> List[int]:
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl32(b, 7)
    return [a, b, c, d]

def u32_to_le_bytes(x: int) -> bytes:
    return struct.pack('<I', x)


# ─── State setup (IETF: 96-bit nonce, 32-bit counter) ──────────────────────────

def chacha20_init_state(key: bytes, counter: int, nonce: bytes) -> List[int]:
    if len(key)   != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    # Constants “expand 32-byte k”
    const = b"expa" + b"nd 3" + b"2-by" + b"te k"
    state = [int.from_bytes(const[i:i+4], 'little') for i in range(0, 16, 4)]

    # Key: 8 words
    state += [int.from_bytes(key[i*4:(i+1)*4], 'little') for i in range(8)]

    # Counter: 1 word
    state.append(counter & 0xFFFFFFFF)

    # Nonce: 3 words
    state += [int.from_bytes(nonce[i*4:(i+1)*4], 'little') for i in range(3)]

    return state


# ─── Block function ───────────────────────────────────────────────────────────

def chacha20_block(state: List[int]) -> bytes:
    w = state.copy()
    for _ in range(10):
        # Column rounds
        w[0], w[4], w[8], w[12]   = quarter_round(w[0], w[4], w[8], w[12])
        w[1], w[5], w[9], w[13]   = quarter_round(w[1], w[5], w[9], w[13])
        w[2], w[6], w[10], w[14]  = quarter_round(w[2], w[6], w[10], w[14])
        w[3], w[7], w[11], w[15]  = quarter_round(w[3], w[7], w[11], w[15])
        # Diagonal rounds
        w[0], w[5], w[10], w[15]  = quarter_round(w[0], w[5], w[10], w[15])
        w[1], w[6], w[11], w[12]  = quarter_round(w[1], w[6], w[11], w[12])
        w[2], w[7], w[8], w[13]   = quarter_round(w[2], w[7], w[8], w[13])
        w[3], w[4], w[9], w[14]   = quarter_round(w[3], w[4], w[9], w[14])

    out = bytearray()
    for i in range(16):
        word = (w[i] + state[i]) & 0xFFFFFFFF
        out += u32_to_le_bytes(word)
    return bytes(out)


# ─── High-level encryption / decryption ────────────────────────────────────────

def chacha20_encrypt(
    plaintext: str,
    key_str: str,
    nonce_str: str,
    initial_counter: int = 1
) -> str:
    """
    Encrypt a UTF-8 plaintext using ChaCha20 (IETF variant).
    Returns the ciphertext as an uppercase hex string.
    """
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    pt_bytes    = utf8_to_bytes(plaintext)

    ciphertext = bytearray()
    ctr = initial_counter
    for offset in range(0, len(pt_bytes), 64):
        chunk     = pt_bytes[offset:offset+64]
        state     = chacha20_init_state(key_bytes, ctr, nonce_bytes)
        keystream = chacha20_block(state)
        for i, b in enumerate(chunk):
            ciphertext.append(b ^ keystream[i])
        ctr += 1

    return bytes_to_hex(bytes(ciphertext))


def chacha20_decrypt(
    cipher_hex: str,
    key_str: str,
    nonce_str: str,
    initial_counter: int = 1
) -> str:
    """
    Decrypt a ChaCha20 ciphertext given as hex.
    Returns the recovered UTF-8 plaintext.
    """
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    ct_bytes    = hex_to_bytes(cipher_hex)

    plaintext = bytearray()
    ctr = initial_counter
    for offset in range(0, len(ct_bytes), 64):
        chunk     = ct_bytes[offset:offset+64]
        state     = chacha20_init_state(key_bytes, ctr, nonce_bytes)
        keystream = chacha20_block(state)
        for i, b in enumerate(chunk):
            plaintext.append(b ^ keystream[i])
        ctr += 1

    return bytes_to_utf8(bytes(plaintext))


# ─── Example usage ────────────────────────────────────────────────────────────

