from typing import Tuple
from utils.useful_functions import (
    utf8_to_bytes, bytes_to_utf8,
    bytes_to_hex, hex_to_bytes,
    chunk_bytes, xor_bytes,
    int_to_bytes
)
from algorithms.symmetric.AES import encrypt_block , _get_aes_params
from algorithms.MAC.Ghash import ghash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BLOCK_SIZE = 16


def _inc_counter(counter: bytearray) -> None:
    """Increment a 128-bit big-endian counter in-place."""
    for i in range(len(counter)-1, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i] != 0:
            break


def gctr(key: bytes, initial_counter: bytes, data: bytes) -> bytes:
    """
    GCTR: AES-CTR style encryption/decryption.
    key: 16/24/32-byte AES key
    initial_counter: 16-byte counter block
    data: plaintext or ciphertext bytes
    """
    out = bytearray()
    ctr = bytearray(initial_counter)
    for block in chunk_bytes(data, BLOCK_SIZE):
        ks = encrypt_block(bytes(ctr), key)
        out.extend(x ^ y for x, y in zip(block, ks[:len(block)]))
        _inc_counter(ctr)
    return bytes(out)


def aes_gcm_encrypt(
    plaintext: str,
    key_str: str,
    nonce_str: str,
    aad: str = ""
) -> Tuple[str, str]:
    """
    AEAD_AES_GCM encryption.
    Returns (ciphertext_hex, tag_hex).
    """
    # 1) Prepare key, IV, plaintext, AAD
    key_length=_get_aes_params(utf8_to_bytes(key_str))[0]*4
    key_bytes   = utf8_to_bytes(key_str)[:key_length].ljust(key_length, b'\x00')
    iv_bytes    = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    pt_bytes    = utf8_to_bytes(plaintext)
    aad_bytes   = utf8_to_bytes(aad)

    # 2) Hash subkey H = AES(K, 0^128)
    H = encrypt_block(b'\x00' * BLOCK_SIZE, key_bytes)

    # 3) Build J0 = IV || 0x00000001
    J0 = iv_bytes + b"\x00\x00\x00\x01"

    # 4) Encrypt plaintext: C = GCTR(K, incr(J0), P)
    icb = bytearray(J0)
    _inc_counter(icb)
    C = gctr(key_bytes, bytes(icb), pt_bytes)

    # 5) Compute GHASH: S = GHASH(H, A, C)
    S = ghash(H, aad_bytes, C)

    # 6) Compute Tag: T = MSB128( AES(K, J0) ^ S )
    E = encrypt_block(J0, key_bytes)
    T = xor_bytes(E, S)

    return bytes_to_hex(C), bytes_to_hex(T)


def aes_gcm_decrypt(
    cipher_hex: str,
    tag_hex: str,
    key_str: str,
    nonce_str: str,
    aad: str = ""
) -> str:
    """
    AEAD_AES_GCM decryption.
    Raises ValueError on authentication failure.
    Returns plaintext string.
    """
    # 1) Prepare key, IV, ciphertext, tag, AAD
    key_legnth=_get_aes_params(utf8_to_bytes(key_str))[0]*4
    key_bytes   = utf8_to_bytes(key_str)[:key_legnth].ljust(key_legnth, b'\x00')
    iv_bytes    = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    C           = hex_to_bytes(cipher_hex)
    received_T  = hex_to_bytes(tag_hex)
    aad_bytes   = utf8_to_bytes(aad)

    # 2) Recompute hash subkey and J0
    H = encrypt_block(b'\x00' * BLOCK_SIZE, key_bytes)
    J0 = iv_bytes + b"\x00\x00\x00\x01"

    # 3) Compute GHASH
    S = ghash(H, aad_bytes, C)

    # 4) Recompute and verify Tag
    E = encrypt_block(J0, key_bytes)
    expected_T = xor_bytes(E, S)
    if expected_T != received_T:
        raise ValueError("AES-GCM: authentication failed")

    # 5) Decrypt: P = GCTR(K, incr(J0), C)
    icb = bytearray(J0)
    _inc_counter(icb)
    P = gctr(key_bytes, bytes(icb), C)

    return bytes_to_utf8(P)



