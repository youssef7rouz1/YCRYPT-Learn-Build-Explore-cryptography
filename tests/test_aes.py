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
    """Return a random ASCII string of the specified byte length."""
    chars = string.printable.strip()
    return ''.join(random.choice(chars) for _ in range(length))

def random_iv_bytes() -> bytes:
    """Return a random IV of BLOCK_SIZE bytes."""
    return os.urandom(BLOCK_SIZE)

def random_plaintext() -> str:
    """Return a random printable string up to 64 characters."""
    length = random.randint(0, 64)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("i", range(40))
def test_ecb_random(key_len, i):
    key = random_key_str(key_len)
    pt_bytes = random_plaintext().encode('utf-8')

    # Reference ECB encryption from PyCryptodome
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    expected_ct = cipher.encrypt(pad(pt_bytes, BLOCK_SIZE)).hex()

    # Our implementation
    ct_hex = encrypt_ecb(pt_bytes.decode('utf-8', errors='ignore'), key)
    assert ct_hex == expected_ct

    # Decrypt back and compare
    decrypted = decrypt_ecb(expected_ct, key)
    assert decrypted == pt_bytes.decode('utf-8', errors='ignore')

@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("i", range(40))
def test_cbc_random(key_len, i):
    key = random_key_str(key_len)
    iv = random_iv_bytes()
    iv_hex = iv.hex()
    pt_bytes = random_plaintext().encode('utf-8')

    # Reference CBC encryption from PyCryptodome
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    expected_ct = cipher.encrypt(pad(pt_bytes, BLOCK_SIZE)).hex()

    # Our implementation
    ct_hex = encrypt_cbc(pt_bytes.decode('utf-8', errors='ignore'), key, iv_hex)
    assert ct_hex == expected_ct

    # Decrypt back and compare
    decrypted = decrypt_cbc(expected_ct, key, iv_hex)
    assert decrypted == pt_bytes.decode('utf-8', errors='ignore')

@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("i", range(40))
def test_ctr_random(key_len, i):
    key = random_key_str(key_len)
    iv = random_iv_bytes()
    iv_int = int.from_bytes(iv, byteorder='big')
    ctr = Counter.new(128, initial_value=iv_int)

    pt_str = random_plaintext()
    pt_bytes = pt_str.encode('utf-8')

    # Reference CTR encryption from PyCryptodome
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, counter=ctr)
    expected_ct = cipher.encrypt(pt_bytes).hex()

    # Our implementation
    ct_hex = encrypt_ctr(pt_str, key, iv.hex())
    assert ct_hex == expected_ct

    # Decrypt back and compare
    decrypted = decrypt_ctr(expected_ct, key, iv.hex())
    assert decrypted == pt_str
