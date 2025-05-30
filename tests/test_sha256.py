import pytest
import random
import string
from Crypto.Hash import SHA256
from algorithms.hashing.sha_256 import sha256

def random_text(max_length: int = 256) -> str:
    """
    Return a random printable string up to max_length.
    """
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_sha256_random(i):
    """
    Compare our sha256 against PyCryptodome on random data.
    """
    text = random_text()
    expected = SHA256.new(text.encode("utf-8")).hexdigest().upper()
    assert sha256(text) == expected

@pytest.mark.parametrize("text", [
    "",
    "a",
    "abc",
    "message digest",
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    string.punctuation,
    "a" * 1000,
])
def test_sha256_known_vectors(text):
    """
    Verify sha256 outputs on known sample strings.
    """
    expected = SHA256.new(text.encode("utf-8")).hexdigest().upper()
    assert sha256(text) == expected
