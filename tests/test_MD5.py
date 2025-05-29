
import pytest
import random
import string
from Crypto.Hash import MD5
from algorithms.hashing.MD5 import md5  

def random_text(max_length: int = 256) -> str:
    """
    Generate a random text string (printable ASCII + whitespace) of length up to max_length.
    """
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_md5_random_printable(i):
 
    text = random_text(256)
    expected = MD5.new(text.encode("utf-8")).hexdigest().upper()
    assert md5(text) == expected

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
def test_md5_various_known(text):
    """
    Test a variety of fixed and special strings.
    """
    expected = MD5.new(text.encode("utf-8")).hexdigest().upper()
    assert md5(text) == expected
