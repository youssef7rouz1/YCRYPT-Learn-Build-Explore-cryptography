import binascii
import random
import string

import pytest
from Crypto.Cipher import ChaCha20_Poly1305

from utils.useful_functions import utf8_to_bytes
from algorithms.AEAD.ChaCha20_Poly1305 import (
    chacha20_poly1305_encrypt,
    chacha20_poly1305_decrypt,
)

def random_key_str() -> str:
    """Generate a random 32-character ASCII key."""
    return ''.join(random.choice(string.printable.strip()) for _ in range(32))

def random_nonce_str() -> str:
    """Generate a random 12-character ASCII nonce."""
    return ''.join(random.choice(string.printable.strip()) for _ in range(12))

def random_plaintext() -> str:
    """Generate a random plaintext up to 200 characters."""
    length = random.randint(0, 200)
    return ''.join(random.choice(string.printable) for _ in range(length))

def random_aad() -> str:
    """Generate random additional authenticated data up to 50 characters."""
    length = random.randint(0, 50)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(50))
def test_chacha20_poly1305_random(i):
    plaintext = random_plaintext()
    key       = random_key_str()
    nonce     = random_nonce_str()
    aad       = random_aad()

    # Encrypt and decrypt with our implementation
    ct_hex, tag_hex = chacha20_poly1305_encrypt(plaintext, key, nonce, aad)
    result = chacha20_poly1305_decrypt(ct_hex, tag_hex, key, nonce, aad)
    assert result == plaintext

    # Verify against PyCryptodome's ChaCha20-Poly1305
    key_bytes   = utf8_to_bytes(key)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce)[:12].ljust(12, b'\x00')
    pt_bytes    = plaintext.encode('utf-8', errors='ignore')
    aad_bytes   = aad.encode('utf-8', errors='ignore')

    aead = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)
    if aad_bytes:
        aead.update(aad_bytes)
    expected_ct = aead.encrypt(pt_bytes)
    expected_tag = aead.digest()

    assert ct_hex.upper() == expected_ct.hex().upper()
    assert tag_hex.upper() == expected_tag.hex().upper()

    # Test decryption and authentication
    aead2 = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)
    if aad_bytes:
        aead2.update(aad_bytes)
    decrypted = aead2.decrypt_and_verify(
        binascii.unhexlify(ct_hex), bytes.fromhex(tag_hex)
    )
    assert decrypted.decode('utf-8', errors='ignore') == plaintext
