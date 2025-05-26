# tests/test_chacha20_poly1305_highlevel.py

import pytest
import random
import string
import binascii

from Crypto.Cipher import ChaCha20_Poly1305

from utils.useful_functions import utf8_to_bytes
from algorithms.AEAD.ChaCha20_Poly1305 import chacha20_poly1305_encrypt , chacha20_poly1305_decrypt


def random_key_str() -> str:
    # up to 32 printable ASCII chars
    return ''.join(random.choice(string.printable.strip()) for _ in range(32))


def random_nonce_str() -> str:
    # up to 12 printable ASCII chars
    return ''.join(random.choice(string.printable.strip()) for _ in range(12))


def random_plaintext() -> str:
    # up to 200 printable characters (including empty)
    length = random.randint(0, 200)
    return ''.join(random.choice(string.printable) for _ in range(length))


def random_aad() -> str:
    # up to 50 printable characters for AAD
    length = random.randint(0, 50)
    return ''.join(random.choice(string.printable) for _ in range(length))


@pytest.mark.parametrize("i", range(50))
def test_chacha20_poly1305_random(i):
    # 1) Random inputs
    pt_str    = random_plaintext()
    key_str   = random_key_str()
    nonce_str = random_nonce_str()
    aad_str   = random_aad()

    # 2) Our implementation round-trip
    ct_hex, tag_hex = chacha20_poly1305_encrypt(pt_str, key_str, nonce_str, aad_str)
    recovered       = chacha20_poly1305_decrypt(ct_hex, tag_hex, key_str, nonce_str, aad_str)
    assert recovered == pt_str
    # ciphertext and tag must be hex strings

    # 3) Cross-check with PyCryptodome AEAD
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    pt_bytes    = pt_str.encode('utf-8', errors='ignore')
    aad_bytes   = aad_str.encode('utf-8', errors='ignore')

    # Built-in AEAD
    aead = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)
    if aad_bytes:
        aead.update(aad_bytes)
    expected_ct = aead.encrypt(pt_bytes)
    expected_tag = aead.digest()

    assert ct_hex.upper() == expected_ct.hex().upper()
    assert tag_hex.upper() == expected_tag.hex().upper()

    # 4) Separate decrypt instance
    aead2 = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)
    if aad_bytes:
        aead2.update(aad_bytes)
    dec_pt = aead2.decrypt_and_verify(binascii.unhexlify(ct_hex), bytes.fromhex(tag_hex))
    assert dec_pt.decode('utf-8', errors='ignore') == pt_str
