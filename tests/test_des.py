# tests/test_des_highlevel.py

import pytest
import random
import string
import binascii
import os

from Crypto.Cipher import DES , DES3
from Crypto.Util.Padding import pad, unpad

from algorithms.symmetric.DES import encrypt_cbc,encrypt_ecb,decrypt_cbc,decrypt_ecb,triple_des_decrypt_cbc,triple_des_decrypt_ecb,triple_des_encrypt_cbc,triple_des_encrypt_ecb

def random_key_des_str() -> str:
    # up to 8 printable ASCII chars (including empty)
    length = random.randint(0, 8)
    return ''.join(random.choice(string.printable.strip()) for _ in range(length))

def random_key_3des_str() -> str:
    # up to 24 printable ASCII chars (including empty)
    length = random.randint(0, 24)
    return ''.join(random.choice(string.printable.strip()) for _ in range(length))

def random_iv_hex() -> str:
    # exactly 16 hex digits = 8 bytes
    return ''.join(random.choice('0123456789ABCDEF') for _ in range(16))


def random_plaintext() -> str:
    # up to 100 printable characters (including empty)
    length = random.randint(0, 100)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(50))
def test_encrypt_decrypt_ecb_random(i):
    pt_str  = random_plaintext()
    key_str = random_key_des_str()

    # Our implementation
    ct_hex      = encrypt_ecb(pt_str, key_str)
    recovered   = decrypt_ecb(ct_hex, key_str)
    assert recovered == pt_str
    assert all(c in string.hexdigits for c in ct_hex)

    # Cross-check with PyCryptodome
    key_bytes   = key_str.encode('utf-8')[:8].ljust(8, b'\x00')
    pt_bytes    = pt_str.encode('utf-8')
    pt_padded   = pad(pt_bytes, DES.block_size)
    cipher_enc  = DES.new(key_bytes, DES.MODE_ECB)
    expected_ct = cipher_enc.encrypt(pt_padded).hex().upper()
    assert ct_hex.upper() == expected_ct

    # Separate decrypt instance
    cipher_dec  = DES.new(key_bytes, DES.MODE_ECB)
    dec_padded  = cipher_dec.decrypt(binascii.unhexlify(ct_hex))
    dec_bytes   = unpad(dec_padded, DES.block_size)
    assert dec_bytes.decode('utf-8', errors='ignore') == pt_str

@pytest.mark.parametrize("i", range(50))
def test_encrypt_decrypt_cbc_random(i):
    pt_str   = random_plaintext()
    key_str  = random_key_des_str()
    iv_bytes = os.urandom(8)
    iv_hex   = iv_bytes.hex().upper()

    # Our implementation
    ct_hex    = encrypt_cbc(pt_str, key_str, iv_hex)
    recovered = decrypt_cbc(ct_hex, key_str, iv_hex)
    assert recovered == pt_str
    assert all(c in string.hexdigits for c in ct_hex)

    # Cross-check with PyCryptodome
    key_bytes  = key_str.encode('utf-8')[:8].ljust(8, b'\x00')
    pt_bytes   = pt_str.encode('utf-8')
    pt_padded  = pad(pt_bytes, DES.block_size)

    cipher_enc = DES.new(key_bytes, DES.MODE_CBC, iv=iv_bytes)
    expected_ct = cipher_enc.encrypt(pt_padded).hex().upper()
    assert ct_hex.upper() == expected_ct

    # Separate decrypt instance
    cipher_dec = DES.new(key_bytes, DES.MODE_CBC, iv=iv_bytes)
    dec_padded = cipher_dec.decrypt(binascii.unhexlify(ct_hex))
    dec_bytes  = unpad(dec_padded, DES.block_size)
    assert dec_bytes.decode('utf-8', errors='ignore') == pt_str



