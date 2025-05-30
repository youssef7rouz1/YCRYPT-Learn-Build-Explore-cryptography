import pytest
import random
import string

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)
from utils.useful_functions import utf8_to_bytes
from algorithms.AEAD.XChaChaPoly1305 import (
    xchacha20_poly1305_encrypt,
    xchacha20_poly1305_decrypt,
)

def random_key_str() -> str:
    """Produce a random 32-character ASCII key."""
    return ''.join(random.choice(string.printable.strip()) for _ in range(32))

def random_nonce_str() -> str:
    """Produce a random 24-character ASCII nonce."""
    return ''.join(random.choice(string.printable.strip()) for _ in range(24))

def random_plaintext() -> str:
    """Generate up to 200 printable characters of random plaintext."""
    length = random.randint(0, 200)
    return ''.join(random.choice(string.printable) for _ in range(length))

def random_aad() -> str:
    """Generate up to 50 printable characters of associated data."""
    length = random.randint(0, 50)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(50))
def test_xchacha20_poly1305_random(i):
    """
    Round-trip test for XChaCha20-Poly1305 and cross-verify against PyNaCl.
    """
    # Prepare random inputs
    plaintext = random_plaintext()
    key       = random_key_str()
    nonce     = random_nonce_str()
    aad       = random_aad()

    # Encrypt and decrypt with our implementation
    ct_hex, tag_hex = xchacha20_poly1305_encrypt(plaintext, key, nonce, aad)
    recovered       = xchacha20_poly1305_decrypt(ct_hex, tag_hex, key, nonce, aad)
    assert recovered == plaintext

    # Cross-check with PyNaCl reference implementation
    key_bytes   = utf8_to_bytes(key)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce)[:24].ljust(24, b'\x00')
    pt_bytes    = utf8_to_bytes(plaintext)
    aad_bytes   = utf8_to_bytes(aad)

    combined     = crypto_aead_xchacha20poly1305_ietf_encrypt(pt_bytes, aad_bytes, nonce_bytes, key_bytes)
    expected_ct  = combined[:-16]
    expected_tag = combined[-16:]

    assert ct_hex.upper() == expected_ct.hex().upper()
    assert tag_hex.upper() == expected_tag.hex().upper()

    # Verify decryption with PyNaCl
    decrypted = crypto_aead_xchacha20poly1305_ietf_decrypt(combined, aad_bytes, nonce_bytes, key_bytes)
    assert decrypted.decode('latin-1') == plaintext
