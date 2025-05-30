# caesar.py

# Simple Caesar cipher for ASCII letters.
# Non-letter characters pass through unchanged.

def encrypt(plaintext: str, shift: int) -> str:
    shift %= 26
    result = []
    for ch in plaintext:
        if 'a' <= ch <= 'z':
            base = ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        elif 'A' <= ch <= 'Z':
            base = ord('A')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def decrypt(ciphertext: str, shift: int) -> str:
    # Reverse shift to decrypt
    return encrypt(ciphertext, -shift)
