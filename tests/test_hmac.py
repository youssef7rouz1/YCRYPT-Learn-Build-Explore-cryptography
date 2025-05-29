import pytest, random, string, hmac, hashlib

# Our implementation under test
from algorithms.HMAC.HMAC import hmac as my_hmac

# ---------------------------------------------------------------------------
# Helper: map our algorithm names → hashlib callables
ALGOS = {
    "SHA-256": hashlib.sha256,
    "SHA-1":   hashlib.sha1,
    "SHA-512":     hashlib.sha512,
    "MD5":     hashlib.md5,
    "SHA3-224":     hashlib.sha3_224,
    "SHA3-256":     hashlib.sha3_256,
    "SHA3-384":     hashlib.sha3_384,
    "SHA3-512":     hashlib.sha3_512,
    

}

# Latin‑1 keeps each code‑point 0x00‑0xFF as the same single byte
latin1 = str.encode

def to_bytes(s: str) -> bytes:
    return latin1(s, "latin-1")

# ---------------------------------------------------------------------------
# Random printable generator (ASCII only, so UTF‑8 and Latin‑1 are identical)

def random_text(max_len: int = 256) -> str:
    return "".join(random.choice(string.printable) for _ in range(random.randint(0, max_len)))

# ---------------------------------------------------------------------------
# 1) 20 random key / message pairs per algorithm (printable ASCII)

@pytest.mark.parametrize("algo", ALGOS.keys())
@pytest.mark.parametrize("_", range(20))
def test_hmac_random_printable(algo, _):
    key = random_text(90)      # cover <, =, > block-size for SHA‑256/MD5/SHA‑1
    msg = random_text(256)
    expected = hmac.new(to_bytes(key), to_bytes(msg), ALGOS[algo]).hexdigest().upper()
    assert my_hmac(key, msg, algo) == expected

# ---------------------------------------------------------------------------
# 2) Edge‑case vectors (short/long keys, empty msg, etc.)

EDGE_VECTORS = [
    ("", ""),
    ("key", "The quick brown fox jumps over the lazy dog"),
    ("k" * 64, "msg"),          # key == block size
    ("k" * 90, "msg"),          # key  > block size
    ("key", "a" * 1000),        # long message
]

@pytest.mark.parametrize("key,msg", EDGE_VECTORS)
@pytest.mark.parametrize("algo", ["SHA-256"])
def test_hmac_edge_cases(algo, key, msg):
    expected = hmac.new(to_bytes(key), to_bytes(msg), hashlib.sha256).hexdigest().upper()
    assert my_hmac(key, msg, algo) == expected
