# tests/test_aes_gcm_random.py

import os
import pytest
import random
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.useful_functions import utf8_to_bytes , bytes_to_utf8
from algorithms.AEAD.AES_GCM import aes_gcm_encrypt, aes_gcm_decrypt

def random_key_str(length: int) -> str:
    """Generate a random printable‐ASCII string of exactly `length` bytes."""
    return ''.join(random.choice(string.printable.strip()) for _ in range(length))


def random_nonce() -> str:
    """Generate a random 12‐byte nonce."""
    return ''.join(random.choice(string.printable.strip()) for _ in range(12))

def random_plaintext() -> str:
    """Generate random printable plaintext up to 64 chars."""
    length = random.randint(0, 64)
    return ''.join(random.choice(string.printable) for _ in range(length))


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("i", range(40))
def test_aes_gcm_random(key_len, i):
    # 1) Prepare random key, nonce, plaintext, empty AAD
    key_str   = random_key_str(key_len)
    key_bytes = utf8_to_bytes(key_str)[:key_len]
    nonce     = random_nonce()
    pt_str    = random_plaintext()
    pt_bytes  = utf8_to_bytes(pt_str)
    aad_bytes = utf8_to_bytes("")

    # 2) Our implementation
    ct_hex, tag_hex = aes_gcm_encrypt(pt_str, key_str, nonce, bytes_to_utf8(aad_bytes))

    # 3) Reference with cryptography.AESGCM
    aesgcm   = AESGCM(key_bytes)
    encrypted = aesgcm.encrypt(utf8_to_bytes(nonce), pt_bytes, aad_bytes)
    ref_ct   = encrypted[:-16]
    ref_tag  = encrypted[-16:]

    assert ct_hex.upper()  == ref_ct.hex().upper()
    assert tag_hex.upper() == ref_tag.hex().upper()

    # 4) Round‐trip decryption
    recovered = aes_gcm_decrypt(ct_hex, tag_hex, key_str, nonce, bytes_to_utf8(aad_bytes))
    assert recovered == pt_str
