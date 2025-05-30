import pytest
from algorithms.symmetric.rc4 import encrypt, decrypt

# RC4 test cases from standard vectors
@pytest.mark.parametrize("plaintext, key, expected", [
    ("Plaintext",      "Key",    "BBF316E8D940AF0AD3"),
    ("pedia",          "Wiki",   "1021BF0420"),
    ("Attack at dawn", "Secret", "45A01F645FC35B383552544B9BF5"),
])
def test_encrypt_rc4(plaintext, key, expected):
    # Encryption should match the known RC4 hex output
    assert encrypt(plaintext, key) == expected

@pytest.mark.parametrize("plaintext, key, expected", [
    ("Plaintext",      "Key",    "BBF316E8D940AF0AD3"),
    ("pedia",          "Wiki",   "1021BF0420"),
    ("Attack at dawn", "Secret", "45A01F645FC35B383552544B9BF5"),
])
def test_decrypt_rc4(plaintext, key, expected):
    # Decryption of the hex string should recover the original text
    assert decrypt(expected, key) == plaintext
