from typing import Tuple
from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_utf8,
    bytes_to_hex,
    hex_to_bytes,
)
from algorithms.symmetric.ChaCha20 import (
    chacha20_init_state,
    chacha20_block,
)
from algorithms.symmetric.ChaCha20 import hchacha20
from algorithms.MAC.poly1305 import poly1305




def xchacha20_poly1305_encrypt(
    plaintext: str,
    key_str: str,
    nonce_str: str,
    aad: str = "",
    initial_counter: int = 1
) -> Tuple[str, str]:
    """
    AEAD-XChaCha20-Poly1305 per RFC: uses HChaCha20+ChaCha20-Poly1305.
    key_str: UTF-8 32-byte key
    nonce_str: UTF-8 24-byte nonce
    aad: associated data
    Returns (ciphertext_hex, tag_hex).
    """
    # 1) Prepare key/nonce/AAD
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:24].ljust(24, b'\x00')
    pt_bytes    = utf8_to_bytes(plaintext)
    aad_bytes   = utf8_to_bytes(aad)

    # 2) Derive subkey via HChaCha20 (first 16 bytes of nonce)
    nonce16 = nonce_bytes[:16]
    subkey  = hchacha20(key_bytes, nonce16)

    # 3) Build AEAD-ChaCha20-Poly1305 nonce: 4 NUL bytes + last 8 bytes of nonce
    nonce12 = b"\x00"*4 + nonce_bytes[16:]

    # 4) Derive one-time Poly1305 key (block counter = 0)
    state0      = chacha20_init_state(subkey, 0, nonce12)
    block0      = chacha20_block(state0)
    one_time_key = block0[:32]

    # 5) Encrypt plaintext (counter starts at 1)
    ciphertext = bytearray()
    ctr = initial_counter
    for off in range(0, len(pt_bytes), 64):
        chunk     = pt_bytes[off:off+64]
        state     = chacha20_init_state(subkey, ctr, nonce12)
        keystream = chacha20_block(state)
        for i, b in enumerate(chunk):
            ciphertext.append(b ^ keystream[i])
        ctr += 1

    ct_bytes = bytes(ciphertext)
    ct_hex   = bytes_to_hex(ct_bytes)

    # 6) Compute Poly1305 tag over AAD and ciphertext
    tag_bytes = poly1305(bytes_to_utf8(one_time_key), bytes_to_utf8(aad_bytes), bytes_to_utf8(ct_bytes))
    tag_hex   = tag_bytes.hex().upper()
    return ct_hex, tag_hex


def xchacha20_poly1305_decrypt(
    cipher_hex: str,
    tag_hex: str,
    key_str: str,
    nonce_str: str,
    aad: str = "",
    initial_counter: int = 1
) -> str:
    """
    AEAD-XChaCha20-Poly1305 decryption and verification.
    Raises ValueError on authentication failure.
    Returns plaintext UTF-8.
    """
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:24].ljust(24, b'\x00')
    ct_bytes    = hex_to_bytes(cipher_hex)
    aad_bytes   = utf8_to_bytes(aad)

    # Derive subkey
    subkey = hchacha20(key_bytes, nonce_bytes[:16])
    nonce12 = b"\x00"*4 + nonce_bytes[16:]

    # Re-derive one-time Poly1305 key
    state0      = chacha20_init_state(subkey, 0, nonce12)
    block0      = chacha20_block(state0)
    one_time_key = block0[:32]

    # Verify tag
    expected = poly1305(bytes_to_utf8(one_time_key), bytes_to_utf8(aad_bytes), bytes_to_utf8(ct_bytes)).hex().upper()
    if expected != tag_hex.upper():
        raise ValueError("XChaCha20-Poly1305: authentication failed")

    # Decrypt ciphertext
    plaintext = bytearray()
    ctr = initial_counter
    for off in range(0, len(ct_bytes), 64):
        chunk     = ct_bytes[off:off+64]
        state     = chacha20_init_state(subkey, ctr, nonce12)
        keystream = chacha20_block(state)
        for i, b in enumerate(chunk):
            plaintext.append(b ^ keystream[i])
        ctr += 1

    return bytes_to_utf8(bytes(plaintext))

