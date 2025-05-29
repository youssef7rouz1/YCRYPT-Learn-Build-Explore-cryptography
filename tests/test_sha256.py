# tests/test_md4_random.py

import pytest
import random
import string
from Crypto.Hash import SHA256
from algorithms.hashing.sha_256 import sha256  # ← replace with the real import path to your md5() function

def random_text(max_length: int = 256) -> str:
    """
    Generate a random text string (printable ASCII + whitespace) of length up to max_length.
    """
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_sha256_random_printable(i):
 
    text = random_text(256)
    expected = SHA256.new(text.encode("utf-8")).hexdigest().upper()
    assert sha256(text) == expected

@pytest.mark.parametrize("text", [
    "",                    # empty
    "a",
    "abc",
    "message digest",
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    string.punctuation,
  
    "a" * 1000,            # long repetition
])
def test_sha256_various_known(text):
    """
    Test a variety of fixed and special strings.
    """
    expected = SHA256.new(text.encode("utf-8")).hexdigest().upper()
    assert sha256(text) == expected
