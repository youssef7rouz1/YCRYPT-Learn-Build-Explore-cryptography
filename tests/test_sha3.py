import pytest
import random
import string
from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512
from algorithms.hashing.SHA3 import sha3_224, sha3_256, sha3_384, sha3_512

def random_text(max_length: int = 256) -> str:
    # Create a random string of printable characters, up to max_length
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_sha3_256_random(i):
    # Compare our SHA3-256 implementation against PyCryptodome on random input
    text = random_text()
    expected = SHA3_256.new(text.encode("utf-8")).hexdigest().upper()
    assert sha3_256(text) == expected

@pytest.mark.parametrize("i", range(20))
def test_sha3_512_random(i):
    # Compare our SHA3-512 implementation against PyCryptodome on random input
    text = random_text()
    expected = SHA3_512.new(text.encode("utf-8")).hexdigest().upper()
    assert sha3_512(text) == expected

@pytest.mark.parametrize("i", range(20))
def test_sha3_224_random(i):
    # Compare our SHA3-224 implementation against PyCryptodome on random input
    text = random_text()
    expected = SHA3_224.new(text.encode("utf-8")).hexdigest().upper()
    assert sha3_224(text) == expected

@pytest.mark.parametrize("i", range(20))
def test_sha3_384_random(i):
    # Compare our SHA3-384 implementation against PyCryptodome on random input
    text = random_text()
    expected = SHA3_384.new(text.encode("utf-8")).hexdigest().upper()
    assert sha3_384(text) == expected

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
def test_sha3_256_known(text):
    # Verify SHA3-256 on a set of known strings
    expected = SHA3_256.new(text.encode("utf-8")).hexdigest().upper()
    assert sha3_256(text) == expected

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
def test_sha3_512_known(text):
    # Verify SHA3-512 on a set of known strings
    expected = SHA3_512.new(text.encode("utf-8")).hexdigest().upper()
    assert sha3_512(text) == expected

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
def test_sha3_224_known(text):
    # Verify SHA3-224 on a set of known strings
    expected = SHA3_224.new(text.encode("utf-8")).hexdigest().upper()
    assert sha3_224(text) == expected

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
def test_sha3_384_known(text):
    # Verify SHA3-384 on a set of known strings
    expected = SHA3_384.new(text.encode("utf-8")).hexdigest().upper()
    assert sha3_384(text) == expected
