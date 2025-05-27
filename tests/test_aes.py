# tests/test_aes_random.py
import os
import pytest
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util import Counter

from algorithms.symmetric.AES import (
    BLOCK_SIZE,
    encrypt_ecb, decrypt_ecb,
    encrypt_cbc, decrypt_cbc,
    encrypt_ctr, decrypt_ctr
)


def random_key_str(length: int) -> str:
    """Generate a random key string of given byte length."""
    return ''.join(random.choice(string.printable.strip()) for _ in range(length))


def random_iv_bytes() -> bytes:
    """Generate a random IV of BLOCK_SIZE bytes."""
    return os.urandom(BLOCK_SIZE)


def random_plaintext() -> str:
    """Generate random printable plaintext up to 64 chars."""
    length = random.randint(0, 64)
    return ''.join(random.choice(string.printable) for _ in range(length))


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("i", range(40))
def test_ecb_random(key_len, i):
    key = random_key_str(key_len)
    pt_bytes = random_plaintext().encode('utf-8')

    # PyCryptodome ECB
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    expected_ct = cipher.encrypt(pad(pt_bytes, BLOCK_SIZE)).hex()

    # our implementation
    ct_hex = encrypt_ecb(pt_bytes.decode('utf-8', errors='ignore'), key)
    assert ct_hex == expected_ct
    # decrypt back
    assert decrypt_ecb(expected_ct, key) == pt_bytes.decode('utf-8', errors='ignore')


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("i", range(40))
def test_cbc_random(key_len, i):
    key = random_key_str(key_len)
    iv = random_iv_bytes()
    iv_hex = iv.hex()
    pt_bytes = random_plaintext().encode('utf-8')

    # PyCryptodome CBC
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    expected_ct = cipher.encrypt(pad(pt_bytes, BLOCK_SIZE)).hex()

    # our implementation
    ct_hex = encrypt_cbc(pt_bytes.decode('utf-8', errors='ignore'), key, iv_hex)
    assert ct_hex == expected_ct
    assert decrypt_cbc(expected_ct, key, iv_hex) == pt_bytes.decode('utf-8', errors='ignore')


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("i", range(40))
def test_ctr_random(key_len, i):
    key = random_key_str(key_len)
    iv = random_iv_bytes()
    iv_int = int.from_bytes(iv, byteorder='big')
    ctr = Counter.new(128, initial_value=iv_int)

    pt_str = random_plaintext()
    pt_bytes = pt_str.encode('utf-8')

    # PyCryptodome CTR
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, counter=ctr)
    expected_ct = cipher.encrypt(pt_bytes).hex()

    # our implementation
    ct_hex = encrypt_ctr(pt_str, key, iv.hex())
    assert ct_hex == expected_ct
    assert decrypt_ctr(expected_ct, key, iv.hex()) == pt_str
