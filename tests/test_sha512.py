import pytest
import random
import string
from Crypto.Hash import SHA512
from algorithms.hashing.sha_512 import sha512

def random_text(max_length: int = 256) -> str:
    """
    Return a random printable string up to max_length.
    """
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_sha512_random_printable(i):
    """
    Compare against PyCryptodome SHA512 on random inputs.
    """
    text = random_text()
    expected = SHA512.new(text.encode("utf-8")).hexdigest().upper()
    assert sha512(text) == expected

@pytest.mark.parametrize("text", [
    "",                           # empty string
    "a",
    "abc",
    "message digest",
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    string.punctuation,
    "a" * 1000,                   # long repetition
])
def test_sha512_known_vectors(text):
    """
    Verify SHA512 output for common test vectors.
    """
    expected = SHA512.new(text.encode("utf-8")).hexdigest().upper()
    assert sha512(text) == expected
