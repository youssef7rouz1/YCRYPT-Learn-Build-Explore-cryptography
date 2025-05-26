from typing import  Tuple
from utils.useful_functions import (
    utf8_to_bytes,
    bytes_to_utf8,
    bytes_to_hex,
    hex_to_bytes,
)
# assume your chacha20_block and clamp/poly1305 from before are imported:
from algorithms.symmetric.ChaCha20 import (
    chacha20_init_state,
    chacha20_block,
)
from algorithms.MAC.poly1305 import poly1305

def chacha20_poly1305_encrypt(
    plaintext: str,
    key_str: str,
    nonce_str: str,
    aad: str = "",
    initial_counter: int = 1
) -> Tuple[str, str]:
    """
    AEAD-ChaCha20-Poly1305 (IETF variant).
    Returns (ciphertext_hex, tag_hex).
    """
    # 1) Prepare key/nonce bytes
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    pt_bytes    = utf8_to_bytes(plaintext)
    aad_bytes   = utf8_to_bytes(aad)

    # 2) Derive one-time Poly1305 key from ChaCha20 block 0
    state0 = chacha20_init_state(key_bytes, 0, nonce_bytes)
    block0 = chacha20_block(state0)
    one_time_key = block0[:32]   # first 32 bytes = r||s

    # 3) Encrypt plaintext with counter starting at 1
    ciphertext = bytearray()
    ctr = initial_counter
    for offset in range(0, len(pt_bytes), 64):
        chunk     = pt_bytes[offset:offset+64]
        st        = chacha20_init_state(key_bytes, ctr, nonce_bytes)
        keystream = chacha20_block(st)
        for i, b in enumerate(chunk):
            ciphertext.append(b ^ keystream[i])
        ctr += 1

    ct_bytes = bytes(ciphertext)
    ct_hex   = bytes_to_hex(ct_bytes)

    # 4) Compute Poly1305 tag over (AAD, ciphertext)
    tag_bytes = poly1305(one_time_key, aad_bytes, ct_bytes)
    tag_hex   = tag_bytes.hex().upper()

    return ct_hex, tag_hex


def chacha20_poly1305_decrypt(
    cipher_hex: str,
    tag_hex: str,
    key_str: str,
    nonce_str: str,
    aad: str = "",
    initial_counter: int = 1
) -> str:
    """
    Verify and decrypt AEAD-ChaCha20-Poly1305.
    Raises ValueError on authentication failure.
    Returns plaintext UTF-8.
    """
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    ct_bytes    = hex_to_bytes(cipher_hex)
    aad_bytes   = utf8_to_bytes(aad)

    # 1) Re-derive one-time Poly1305 key
    state0 = chacha20_init_state(key_bytes, 0, nonce_bytes)
    block0 = chacha20_block(state0)
    one_time_key = block0[:32]

    # 2) Verify tag
    expected_tag = poly1305(one_time_key, aad_bytes, ct_bytes).hex().upper()
    if expected_tag != tag_hex.upper():
        raise ValueError("ChaCha20-Poly1305: authentication failed")

    # 3) Decrypt by XORing with keystream blocks
    plaintext = bytearray()
    ctr = initial_counter
    for offset in range(0, len(ct_bytes), 64):
        chunk     = ct_bytes[offset:offset+64]
        st        = chacha20_init_state(key_bytes, ctr, nonce_bytes)
        keystream = chacha20_block(st)
        for i, b in enumerate(chunk):
            plaintext.append(b ^ keystream[i])
        ctr += 1

    return bytes_to_utf8(bytes(plaintext))


