

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
    # up to 32 printable ASCII chars
    return ''.join(random.choice(string.printable.strip()) for _ in range(32))


def random_nonce_str() -> str:
    # up to 24 printable ASCII chars
    return ''.join(random.choice(string.printable.strip()) for _ in range(24))


def random_plaintext() -> str:
    # up to 200 printable characters (including empty)
    length = random.randint(0, 200)
    return ''.join(random.choice(string.printable) for _ in range(length))


def random_aad() -> str:
    # up to 50 printable characters for AAD
    length = random.randint(0, 50)
    return ''.join(random.choice(string.printable) for _ in range(length))


@pytest.mark.parametrize("i", range(50))
def test_xchacha20_poly1305_random(i):
    # 1) Random inputs
    pt_str    = random_plaintext()
    key_str   = random_key_str()
    nonce_str = random_nonce_str()
    aad_str   = random_aad()

    # 2) Our implementation round-trip
    ct_hex, tag_hex = xchacha20_poly1305_encrypt(
        pt_str, key_str, nonce_str, aad_str
    )
    recovered = xchacha20_poly1305_decrypt(
        ct_hex, tag_hex, key_str, nonce_str, aad_str
    )
    assert recovered == pt_str

    # 3) Cross-check with PyNaCl AEAD XChaCha20-Poly1305
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:24].ljust(24, b'\x00')
    pt_bytes    = utf8_to_bytes(pt_str)
    aad_bytes   = utf8_to_bytes(aad_str)

    # Built-in AEAD
    ct_and_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(pt_bytes , aad_bytes , nonce_bytes , key_bytes)
    expected_ct  = ct_and_tag[:-16]
    expected_tag = ct_and_tag[-16:]

    # Compare hex
    assert ct_hex.upper() == expected_ct.hex().upper()
    assert tag_hex.upper() == expected_tag.hex().upper()

    # 4) Decrypt & verify with PyNaCl
    dec_pt = crypto_aead_xchacha20poly1305_ietf_decrypt(ct_and_tag , aad_bytes , nonce_bytes , key_bytes)
    assert dec_pt.decode('utf-8', errors='ignore') == pt_str
