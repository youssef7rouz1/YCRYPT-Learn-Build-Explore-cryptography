import pytest
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter

from algorithms.symmetric.AES_256 import encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc , encrypt_ctr , decrypt_ctr

def random_key() -> str:
    # 16 printable ASCII chars
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

def random_iv_bytes() -> bytes:
    # 16 random bytes
    return random.randbytes(16)

def random_plaintext() -> str:
    # pick a random length from 0→64 and fill with printable chars
    length = random.randrange(0, 65)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_ecb_random(i):
    key = random_key()
    pt = random_plaintext().encode('utf-8')
    # compute expected with PyCryptodome
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    expected_ct = cipher.encrypt(pad(pt, AES.block_size)).hex()
    # test our implementation
    actual_ct = encrypt_ecb(pt.decode('utf-8', errors='ignore'), key)
    assert actual_ct == expected_ct
    # test decrypt back
    assert decrypt_ecb(expected_ct, key) == pt.decode('utf-8', errors='ignore')

@pytest.mark.parametrize("i", range(20))
def test_cbc_random(i):
    key = random_key()
    iv = random_iv_bytes()
    iv_hex = iv.hex()
    pt = random_plaintext().encode('utf-8')
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    expected_ct = cipher.encrypt(pad(pt, AES.block_size)).hex()
    # test our implementation
    actual_ct = encrypt_cbc(pt.decode('utf-8', errors='ignore'), key, iv_hex)
    assert actual_ct == expected_ct
    # test decrypt back
    assert decrypt_cbc(expected_ct, key, iv_hex) == pt.decode('utf-8', errors='ignore')


@pytest.mark.parametrize("i", range(20))
def test_ctr_random(i):
    key = random_key()
    iv = random_iv_bytes()
    iv_hex = iv.hex()

    # plaintext as string and bytes
    pt_str = random_plaintext()
    pt = pt_str.encode('utf-8')

    # PyCryptodome CTR cipher expects bytes
    iv_int = int.from_bytes(iv, byteorder='big')
    ctr = Counter.new(128, initial_value=iv_int)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CTR, counter=ctr)

    expected_ct = cipher.encrypt(pt).hex()

    # test our implementation (which takes plaintext string + key + iv_hex)
    actual_ct = encrypt_ctr(pt_str, key, iv_hex)
    assert actual_ct == expected_ct

    # test decrypt back (returns string)
    recovered = decrypt_ctr(expected_ct, key, iv_hex)
    assert recovered == pt_str
