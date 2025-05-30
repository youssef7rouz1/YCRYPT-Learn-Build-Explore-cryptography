# tests/test_aes_gcm_random.py

import random
import string
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.useful_functions import utf8_to_bytes, bytes_to_utf8
from algorithms.AEAD.AES_GCM import aes_gcm_encrypt, aes_gcm_decrypt

def random_key_str(length: int) -> str:
    """Return a random ASCII key of the specified length."""
    chars = string.printable.strip()
    return ''.join(random.choice(chars) for _ in range(length))

def random_nonce() -> str:
    """Return a random 12-character nonce."""
    chars = string.printable.strip()
    return ''.join(random.choice(chars) for _ in range(12))

def random_plaintext() -> str:
    """Return a random printable string up to 64 characters."""
    length = random.randint(0, 64)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("i", range(40))
def test_aes_gcm_random(key_len, i):
    # Prepare inputs
    key_str   = random_key_str(key_len)
    key_bytes = utf8_to_bytes(key_str)[:key_len]
    nonce     = random_nonce()
    plaintext = random_plaintext()
    pt_bytes  = utf8_to_bytes(plaintext)
    aad_str   = ""
    aad_bytes = utf8_to_bytes(aad_str)

    # Encrypt with our implementation
    ct_hex, tag_hex = aes_gcm_encrypt(plaintext, key_str, nonce, aad_str)

    # Encrypt with cryptography.AESGCM for reference
    aesgcm   = AESGCM(key_bytes)
    encrypted = aesgcm.encrypt(utf8_to_bytes(nonce), pt_bytes, aad_bytes)
    ref_ct   = encrypted[:-16]
    ref_tag  = encrypted[-16:]

    # Compare ciphertext and tag
    assert ct_hex.upper()  == ref_ct.hex().upper()
    assert tag_hex.upper() == ref_tag.hex().upper()

    # Decrypt back and verify
    recovered = aes_gcm_decrypt(ct_hex, tag_hex, key_str, nonce, aad_str)
    assert recovered == plaintext
