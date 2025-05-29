
import pytest
import random
import string
from Crypto.Hash import SHA3_256 , SHA3_512 , SHA3_224 , SHA3_384
from algorithms.hashing.SHA3 import sha3_512 , sha3_256  , sha3_224 , sha3_384

def random_text(max_length: int = 256) -> str:
    """
    Generate a random text string (printable ASCII + whitespace) of length up to max_length.
    """
    length = random.randint(0, max_length)
    return ''.join(random.choice(string.printable) for _ in range(length))

@pytest.mark.parametrize("i", range(20))
def test_sha3_256_random_printable(i):
 
    text = random_text(256)
    expected = SHA3_256.new(text.encode("utf-8")).hexdigest().upper()
   
    assert sha3_256(text) == expected

@pytest.mark.parametrize("i", range(20))
def test_sha3_512_random_printable(i):
 
    text = random_text(256)
    expected = SHA3_512.new(text.encode("utf-8")).hexdigest().upper()
    

    assert sha3_512(text) == expected


@pytest.mark.parametrize("i", range(20))
def test_sha3_224_random_printable(i):
 
    text = random_text(256)
    expected = SHA3_224.new(text.encode("utf-8")).hexdigest().upper()
    
    assert sha3_224(text) == expected

@pytest.mark.parametrize("i", range(20))
def test_sha3_384_random_printable(i):
 
    text = random_text(256)
    expected = SHA3_384.new(text.encode("utf-8")).hexdigest().upper()

    assert sha3_384(text) == expected

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
def test_sha3_256_various_known(text):
    """
    Test a variety of fixed and special strings.
    """
    expected = SHA3_256.new(text.encode("utf-8")).hexdigest().upper()
    
    assert sha3_256(text) == expected



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
def test_sha3_512_various_known(text):
    """
    Test a variety of fixed and special strings.
    """
    expected = SHA3_512.new(text.encode("utf-8")).hexdigest().upper()
  
    assert sha3_512(text) == expected



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
def test_sha3_224_various_known(text):
    """
    Test a variety of fixed and special strings.
    """
    expected = SHA3_224.new(text.encode("utf-8")).hexdigest().upper()
  
    assert sha3_224(text) == expected



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
def test_sha3_384_various_known(text):
    """
    Test a variety of fixed and special strings.
    """
    expected = SHA3_384.new(text.encode("utf-8")).hexdigest().upper()
    
    assert sha3_384(text) == expected