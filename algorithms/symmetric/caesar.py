"""
Caesar cipher implementation.

Functions:
- encrypt(plaintext: str, shift: int) -> str
- decrypt(ciphertext: str, shift: int) -> str

Supports ASCII letters; preserves case; leaves non-letters unchanged.
"""
def encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypts plaintext using Caesar cipher.
    :param plaintext: Input text to encrypt.
    :param shift: Number of positions to shift (can be negative or >26).
    :return: Encrypted ciphertext.
    """
    result = []
    shift = shift % 26  # normalize large shifts
    for ch in plaintext:
        if 'a' <= ch <= 'z':
            start = ord('a')
            result.append(chr((ord(ch) - start + shift) % 26 + start))
        elif 'A' <= ch <= 'Z':
            start = ord('A')
            result.append(chr((ord(ch) - start + shift) % 26 + start))
        else:
            result.append(ch)
    return ''.join(result)
def decrypt(ciphertext: str, shift: int) -> str:
    """
    Decrypts ciphertext using Caesar cipher by reversing the shift.
    :param ciphertext: Encrypted text.
    :param shift: Number of positions originally used to shift.
    :return: Decrypted plaintext.
    """
    # decryption is just encryption with negative shift
    return encrypt(ciphertext, -shift)