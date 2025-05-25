# tests/test_chacha20_highlevel.py

import pytest
import random
import string
import binascii

from Crypto.Cipher import ChaCha20

from algorithms.symmetric.ChaCha20 import (
    chacha20_encrypt,
    chacha20_decrypt,
)
from utils.conversion_padding_functions import utf8_to_bytes

def random_key_str() -> str:
    
    return ''.join(random.choice(string.printable.strip()) for _ in range(32))

def random_nonce_str() -> str:
    # up to 12 printable ASCII chars
    length = random.randint(1, 12)
    return ''.join(random.choice(string.printable.strip()) for _ in range(length))

def random_plaintext() -> str:
    # up to 200 printable characters (including empty)
    length = random.randint(0, 200)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_chacha20_random(i):
    # 1) Random inputs
    pt_str    = random_plaintext()
    key_str   = random_key_str()
    nonce_str = random_nonce_str()

    # 2) Our implementation round-trip
    ct_hex    = chacha20_encrypt(pt_str, key_str, nonce_str)
    recovered = chacha20_decrypt(ct_hex, key_str, nonce_str)
    assert recovered == pt_str
    # ciphertext must be hex
    assert isinstance(ct_hex, str)
    assert all(c in string.hexdigits for c in ct_hex)

    # 3) Cross-check with PyCryptodome
    key_bytes   = utf8_to_bytes(key_str)[:32].ljust(32, b'\x00')
    nonce_bytes = utf8_to_bytes(nonce_str)[:12].ljust(12, b'\x00')
    pt_bytes    = pt_str.encode('utf-8')

    cipher_enc  = ChaCha20.new(key=key_bytes, nonce=nonce_bytes)
    expected_ct = cipher_enc.encrypt(pt_bytes).hex().upper()
    assert ct_hex.upper() == expected_ct

    # 4) Fresh decrypt instance
    cipher_dec = ChaCha20.new(key=key_bytes, nonce=nonce_bytes)
    dec_bytes  = cipher_dec.decrypt(binascii.unhexlify(ct_hex))
    assert dec_bytes.decode('utf-8', errors='ignore') == pt_str
