import pytest
import random
import string
from Crypto.Hash import MD5
from algorithms.hashing.MD5 import md5

def random_text(max_length: int = 256) -> str:
    """Return a random printable string up to max_length."""
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_md5_random_input(i):
    """MD5 should match PyCryptodome for random inputs."""
    text = random_text()
    expected = MD5.new(text.encode("utf-8")).hexdigest().upper()
    assert md5(text) == expected

@pytest.mark.parametrize("text", [
    "", "a", "abc", "message digest",
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    string.punctuation,
    "a" * 1000,
])
def test_md5_known_vectors(text):
    """MD5 should produce correct digests for known strings."""
    expected = MD5.new(text.encode("utf-8")).hexdigest().upper()
    assert md5(text) == expected
