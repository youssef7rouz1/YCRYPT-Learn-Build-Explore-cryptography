"""
Playfair cipher implementation.

Functions:
- generate_key_matrix(key: str, alphabet: str = ...) -> List[List[str]]
- preprocess_text(text: str, alphabet: str = ...) -> Tuple[List[Tuple[str,str]], List[int]]
- find_position(ch: str, matrix: List[List[str]]) -> Tuple[int,int]
- encrypt_digraph(pair: Tuple[str,str], matrix: List[List[str]]) -> Tuple[str,str]
- decrypt_digraph(pair: Tuple[str,str], matrix: List[List[str]]) -> Tuple[str,str]
- encrypt(plaintext: str, key: str, alphabet: str = ...) -> str
- decrypt(ciphertext: str, key: str, alphabet: str = ...) -> str

This version maps 'J' to 'I', preserves spaces, and uses uppercase internally.
"""
from typing import List, Tuple


def generate_key_matrix(
    key: str,
    alphabet: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
) -> List[List[str]]:
    """
    Builds a 5×5 key matrix for Playfair: maps J→I, dedups key, fills remaining letters.
    """
    key = key.upper().replace('J', 'I')
    # Keep only valid letters
    key = ''.join(ch for ch in key if ch in alphabet)

    seen = set()
    unique = []
    for ch in key:
        if ch not in seen:
            seen.add(ch)
            unique.append(ch)

    # Append remaining alphabet letters
    for ch in alphabet:
        if ch not in seen:
            unique.append(ch)

    size = int(len(alphabet) ** 0.5)
    return [unique[i*size:(i+1)*size] for i in range(size)]


def preprocess_text(
    text: str,
    alphabet: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
) -> Tuple[List[Tuple[str,str]], List[int]]:
    """
    Cleans input: maps J→I, uppercases, removes non-letters, records spaces,
    then splits into digraphs inserting 'X' between identical letters or at end.
    Returns list of 2-letter tuples and original space indices.
    """
    spaces = [i for i, ch in enumerate(text) if ch == ' ']
    clean = ''.join(
        ch for ch in text.upper().replace('J', 'I')
        if ch in alphabet
    )

    digraphs: List[Tuple[str,str]] = []
    i = 0
    while i < len(clean):
        a = clean[i]
        if i + 1 < len(clean) and clean[i+1] != a:
            b = clean[i+1]
            i += 2
        else:
            b = 'X'
            i += 1
        digraphs.append((a, b))

    return digraphs, spaces


def find_position(
    ch: str,
    matrix: List[List[str]]
) -> Tuple[int,int]:
    """
    Finds row, col of character in the 5×5 matrix.
    """
    for r, row in enumerate(matrix):
        for c, val in enumerate(row):
            if val == ch:
                return r, c
    raise ValueError(f"Character {ch!r} not found in key matrix")


def encrypt_digraph(
    pair: Tuple[str,str],
    matrix: List[List[str]]
) -> Tuple[str,str]:
    """
    Encrypts a two-letter digraph using Playfair rules.
    """
    r1, c1 = find_position(pair[0], matrix)
    r2, c2 = find_position(pair[1], matrix)
    size = len(matrix)

    if r1 == r2:
        return matrix[r1][(c1 + 1) % size], matrix[r2][(c2 + 1) % size]
    if c1 == c2:
        return matrix[(r1 + 1) % size][c1], matrix[(r2 + 1) % size][c2]
    return matrix[r1][c2], matrix[r2][c1]


def decrypt_digraph(
    pair: Tuple[str,str],
    matrix: List[List[str]]
) -> Tuple[str,str]:
    """
    Decrypts a two-letter digraph using inverse Playfair rules.
    """
    r1, c1 = find_position(pair[0], matrix)
    r2, c2 = find_position(pair[1], matrix)
    size = len(matrix)

    if r1 == r2:
        return matrix[r1][(c1 - 1) % size], matrix[r2][(c2 - 1) % size]
    if c1 == c2:
        return matrix[(r1 - 1) % size][c1], matrix[(r2 - 1) % size][c2]
    return matrix[r1][c2], matrix[r2][c1]


def encrypt(
    plaintext: str,
    key: str,
    alphabet: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
) -> str:
    """
    End-to-end Playfair encryption: preserves spaces and uses 'X' padding.
    """
    matrix = generate_key_matrix(key, alphabet)
    digraphs, spaces = preprocess_text(plaintext, alphabet)
    cipher_chars: List[str] = []

    for pair in digraphs:
        a, b = encrypt_digraph(pair, matrix)
        cipher_chars.extend([a, b])

    for pos in spaces:
        cipher_chars.insert(pos, ' ')

    return ''.join(cipher_chars)


def decrypt(
    ciphertext: str,
    key: str,
    alphabet: str = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
) -> str:
    """
    End-to-end Playfair decryption: reverses encrypt, preserves spaces.
    """
    matrix = generate_key_matrix(key, alphabet)
    digraphs, spaces = preprocess_text(ciphertext, alphabet)
    plain_chars: List[str] = []

    for pair in digraphs:
        a, b = decrypt_digraph(pair, matrix)
        plain_chars.extend([a, b])

    for pos in spaces:
        plain_chars.insert(pos, ' ')

    return ''.join(plain_chars)


print(encrypt("hide the gold in the tree stump","playfair example"))
print(decrypt("BMOD ZBX DNAB EK UDM UIXM MOUVIF","playfair example"))