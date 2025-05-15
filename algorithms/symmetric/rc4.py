"""
RC4 stream cipher implementation.


- encrypt(plaintext: str, key: str) -> str        # returns ciphertext as uppercase hex
- decrypt(ciphertext_hex: str, key: str) -> str   # accepts hex, returns plaintext


- _str_to_bytes(s: str) -> bytes
- ksa(key_bytes: bytes) -> List[int]
- prga(state: List[int]) -> Iterator[int]
- generate_keystream(key_bytes: bytes, length: int) -> bytes
"""
from typing import Iterator, List


def _str_to_bytes(s: str, encoding: str = 'utf-8') -> bytes:
    """
    Encode a Python string into bytes using the specified encoding.
    
    """
    
    return s.encode(encoding)


def ksa(key_bytes: bytes) -> List[int]:
    """
    Key-Scheduling Algorithm (KSA).
    
    """
    key_length = len(key_bytes)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % key_length]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S


def prga(state: List[int]) -> Iterator[int]:
    """
    Pseudo-Random Generation Algorithm (PRGA).
    
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
    runs KSA then PRGA to produce exactly `length` keystream bytes.
    """
    state = ksa(key_bytes)
    stream = prga(state)
    return bytes(next(stream) for _ in range(length))


def encrypt(plaintext: str, key: str) -> str:
    """
    Encrypts a text string with RC4 using the provided key string.
    Returns the ciphertext as an uppercase hex string (no prefix).
    """
    pt_bytes = _str_to_bytes(plaintext)
    key_bytes = _str_to_bytes(key)
    keystream = generate_keystream(key_bytes, len(pt_bytes))
    ct_bytes = bytes(p ^ k for p, k in zip(pt_bytes, keystream))
    return ct_bytes.hex().upper()


def decrypt(ciphertext_hex: str, key: str) -> str:
    """
    Decrypts an RC4 ciphertext (hex string) with the provided key string.
    Returns the resulting plaintext string.
    """
    
    ct_bytes = bytes.fromhex(ciphertext_hex)
    key_bytes = _str_to_bytes(key)
    keystream = generate_keystream(key_bytes, len(ct_bytes))
    pt_bytes = bytes(c ^ k for c, k in zip(ct_bytes, keystream))
    return pt_bytes.decode('utf-8', errors='replace')


