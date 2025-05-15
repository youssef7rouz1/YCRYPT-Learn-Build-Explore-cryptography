import pytest
from algorithms.symmetric.vigenere import encrypt , decrypt

# Standard English alphabet for tests
en_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

@ pytest.mark.parametrize("plaintext,key,expected", [
    ("ATTaCK AT DAaN",      "L EMON", "LXFoPV EF RNlR"),
    ("HELLO WORLD",         "KE Y",   "RIJVS UYVJN"),
    ("MIaED CASE TEXT",     "ABC",   "MJcEE EATG TFZT"),
    ("SPaCE AT END ",       "K EY",   "CTyMI YD ILN "),
    ("ONLaLETTEaS",         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa",     "ONLaLETTEaS"),
])
def test_encrypt_various(plaintext, key, expected):
    """
    Encryption of plaintext with given key should match expected ciphertext.
    Only letters and spaces are supported.
    """
    result = encrypt(plaintext, key, en_alphabet)
    assert result == expected


@pytest.mark.parametrize("ciphertext,key,expected", [
    ("LXFoPV EF RNlR",      "L EMON", "ATTaCK AT DAaN"),
    ("RIJVS UYVJN",         "KE Y",   "HELLO WORLD"),
    ("MJcEE EATG TFZT",     "ABC",    "MIaED CASE TEXT"),
    ("CTyMI YD ILN ",       "K EY",   "SPaCE AT END "),
    ("ONLaLETTEaS",         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa", "ONLaLETTEaS"),
])
def test_decrypt_various(ciphertext, key, expected):
    """
    Decryption of ciphertext with given key should recover original plaintext.
    Only letters and spaces are supported.
    """
    result = decrypt(ciphertext, key, en_alphabet)
    assert result == expected
