# tests/test_md4_random.py

import pytest
import random
import string
from Crypto.Hash import MD4
from algorithms.hashing.MD_4 import md4  # ← replace with the real import path to your md4() function

def random_text(max_length: int = 256) -> str:
    """
    Generate a random text string (printable ASCII + whitespace) of length up to max_length.
    """
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_md4_random_printable(i):
    """
    Twenty random tests on printable-ASCII strings up to 256 chars.
    Compare our md4() on the string to PyCryptodome's MD4 on its UTF-8 bytes.
    """
    text = random_text(256)
    # PyCryptodome produces a lowercase hex digest; we uppercase to match our md4()
    expected = MD4.new(text.encode("utf-8")).hexdigest().upper()
    assert md4(text) == expected

@pytest.mark.parametrize("text", [
    "",                    # empty
    "a",
    "abc",
    "message digest",
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    string.punctuation,
    "Café",                # accented
    "こんにちは",          # Japanese
    "👩‍💻👨‍🔧",            # emojis + ZWJ
    "𠜎𠜱𠝹",               # rare CJK characters
    "a" * 1000,            # long repetition
])
def test_md4_various_known(text):
    """
    Test a variety of fixed and special strings.
    """
    expected = MD4.new(text.encode("utf-8")).hexdigest().upper()
    assert md4(text) == expected
