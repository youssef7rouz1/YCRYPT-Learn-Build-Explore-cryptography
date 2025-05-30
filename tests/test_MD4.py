import pytest
import random
import string
from Crypto.Hash import MD4
from algorithms.hashing.MD4 import md4

def random_text(max_length: int = 256) -> str:
    """Return a random printable-ASCII string."""
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_md4_random_inputs(i):
    """Compare md4() output to PyCryptodome for random strings."""
    text = random_text()
    expected = MD4.new(text.encode("utf-8")).hexdigest().upper()
    assert md4(text) == expected

@pytest.mark.parametrize("text", [
    "", "a", "abc", "message digest",
    string.ascii_lowercase, string.ascii_uppercase,
    string.digits, string.punctuation,
    "a" * 1000,
])
def test_md4_known_vectors(text):
    """Verify md4() matches known digests for several cases."""
    expected = MD4.new(text.encode("utf-8")).hexdigest().upper()
    assert md4(text) == expected
