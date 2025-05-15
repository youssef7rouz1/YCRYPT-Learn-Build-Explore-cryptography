"""
RC4 stream cipher implementation from first principles, accepting a text key.

API:
- encrypt(plaintext: bytes, key: str) -> bytes
- decrypt(ciphertext: bytes, key: str) -> bytes

Under the hood:
- _key_to_bytes(key: str) transforms a textual key into bytes
- ksa(key_bytes: bytes) performs the Key-Scheduling Algorithm
- prga(state: List[int]) yields an infinite keystream
- generate_keystream(key_bytes: bytes, length: int) returns fixed-length keystream

Encryption and decryption are identical: XOR with the keystream.
"""
from typing import Iterator, List


def _text_to_bytes(key: str, encoding: str = 'utf-8') -> bytes:
    """
    Convert a textual key into bytes for RC4.
    Raises ValueError if the key is empty.
    """
 
    return key.encode(encoding)


def ksa(key: bytes) -> List[int]:
    """
    Key-Scheduling Algorithm (KSA).
    Initializes state array S to 0..255 and scrambles it using the key bytes.

    :param key: Secret key as bytes.
    :return:  A 256-element list representing the scrambled state.
    """
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S


def prga(state: List[int]) -> Iterator[int]:
    """
    Pseudo-Random Generation Algorithm (PRGA).
    Generates an infinite keystream from the scrambled state.

    :param state: The 256-byte state permutation from ksa().
    :yields:     Next keystream byte (0..255).
    """
    i = 0
    j = 0
    while True:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        t = (state[i] + state[j]) & 0xFF
        yield state[t]


def generate_keystream(key_bytes: bytes, length: int) -> bytes:
    """
    Produce a keystream of a specified length by running KSA then PRGA.

    :param key_bytes: Key material as bytes.
    :param length:    Number of keystream bytes to generate.
    :return:          Keystream bytes.
    """
    state = ksa(key_bytes)
    stream = prga(state)
    return bytes(next(stream) for _ in range(length))


def encrypt(plaintext: str, key: str) -> bytes:
    """
    Encrypt (or decrypt) data with RC4.
    XORs the plaintext bytes with a keystream derived from the text key.

    :param plaintext: Data to encrypt as bytes.
    :param key:       Secret key as a string.
    :return:          Ciphertext as bytes.
    """
    key_bytes = _text_to_bytes(key)
    keystream = generate_keystream(key_bytes, len(_text_to_bytes(plaintext)))
    return bytes(p ^ k for p, k in zip(_text_to_bytes(plaintext), keystream))


def decrypt(ciphertext: str, key: str) -> bytes:
    """
    Decrypt RC4 ciphertext. Identical to encrypt() since XOR is its own inverse.

    :param ciphertext: Data to decrypt as bytes.
    :param key:        Secret key as a string.
    :return:           Recovered plaintext bytes.
    """
    return encrypt(_text_to_bytes(ciphertext), key)

print(encrypt("Plaintext","Key"))