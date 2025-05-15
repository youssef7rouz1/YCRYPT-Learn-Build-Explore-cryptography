import pytest
from algorithms.symmetric.rc4 import encrypt, decrypt

# Test vectors from the RC4 wiki and known references
# Each tuple: (plaintext, key, expected_cipher_hex)

@pytest.mark.parametrize("plaintext, key, expected", [
    ("Plaintext",        "Key",    "BBF316E8D940AF0AD3"),
    ("pedia",            "Wiki",   "1021BF0420"),
    ("Attack at dawn",   "Secret", "45A01F645FC35B383552544B9BF5"),
])
def test_encrypt_rc4(plaintext, key, expected):
    """
    Encryption of plaintext with RC4 under the given key should match
    the expected ciphertext hex string.
    """
    result = encrypt(plaintext, key)
    assert result == expected

@pytest.mark.parametrize("plaintext, key, expected", [
    ("Plaintext",        "Key",    "BBF316E8D940AF0AD3"),
    ("pedia",            "Wiki",   "1021BF0420"),
    ("Attack at dawn",   "Secret", "45A01F645FC35B383552544B9BF5"),
])
def test_decrypt_rc4(plaintext, key, expected):
    """
    Decryption of the given ciphertext hex string should recover the original plaintext.
    """
    result = decrypt(expected, key)
    assert result == plaintext
