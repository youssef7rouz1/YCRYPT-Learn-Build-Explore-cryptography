import pytest
import random
import string
import hmac
import hashlib

from algorithms.HMAC.HMAC import hmac as my_hmac

# Map algorithm names to hashlib implementations
ALGORITHM_MAP = {
    "SHA_256": hashlib.sha256,
    "SHA_1":   hashlib.sha1,
    "SHA_512": hashlib.sha512,
    "MD5":     hashlib.md5,
    "SHA3_224": hashlib.sha3_224,
    "SHA3_256": hashlib.sha3_256,
    "SHA3_384": hashlib.sha3_384,
    "SHA3_512": hashlib.sha3_512,
}

def latin1_bytes(text: str) -> bytes:
    """Encode a string using Latin-1, preserving each character as one byte."""
    return text.encode("latin-1")

def random_text(max_len: int = 256) -> str:
    """Generate a random printable-ASCII string up to max_len characters."""
    length = random.randint(0, max_len)
    return "".join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("algo", ALGORITHM_MAP.keys())
@pytest.mark.parametrize("_", range(20))
def test_hmac_random_printable(algo, _):
    """HMAC should match Python’s `hmac` for random keys and messages."""
    key = random_text(90)   # test keys shorter, equal, and longer than block size
    msg = random_text(256)
    expected = hmac.new(
        latin1_bytes(key),
        latin1_bytes(msg),
        ALGORITHM_MAP[algo]
    ).hexdigest().upper()
    assert my_hmac(key, msg, algo) == expected

EDGE_CASES = [
    ("", ""),
    ("key", "The quick brown fox jumps over the lazy dog"),
    ("k" * 64, "msg"),        # key exactly one block
    ("k" * 90, "msg"),        # key longer than one block
    ("key", "a" * 1000),      # very long message
]

