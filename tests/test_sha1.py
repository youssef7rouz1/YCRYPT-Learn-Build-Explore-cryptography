import pytest
import random
import string
from Crypto.Hash import SHA1
from algorithms.hashing.SHA1 import sha1

def random_text(max_length: int = 256) -> str:
    # Create a random string of printable characters up to the given length
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_sha1_random(i):
    # Compare our SHA1 implementation against PyCryptodome on random input
    text = random_text()
    expected = SHA1.new(text.encode("utf-8")).hexdigest().upper()
    assert sha1(text) == expected

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
def test_sha1_known_strings(text):
    # Verify SHA1 output on a variety of fixed inputs
    expected = SHA1.new(text.encode("utf-8")).hexdigest().upper()
    assert sha1(text) == expected
