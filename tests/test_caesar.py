import pytest
from algorithms.symmetric.caesar import encrypt, decrypt

@pytest.mark.parametrize("plaintext,shift,expected", [
    ("abc", 3, "def"),
    ("xyz", 2, "zab"),
    ("Hello, World!", 5, "Mjqqt, Btwqi!"),
    ("Attack at dawn", 13, "Nggnpx ng qnja"),
    ("Mixed CASE 123!", 4, "Qmbih GEWI 123!")
])
def test_encrypt(plaintext, shift, expected):
    assert encrypt(plaintext, shift) == expected

@pytest.mark.parametrize("ciphertext,shift,expected", [
    ("def", 3, "abc"),
    ("zab", 2, "xyz"),
    ("Mjqqt, Btwqi!", 5, "Hello, World!"),
    ("Nggnpx ng qnja", 13, "Attack at dawn"),
    ("Qmbih GEWI 123!", 4, "Mixed CASE 123!")
])
def test_decrypt(ciphertext, shift, expected):
    assert decrypt(ciphertext, shift) == expected
