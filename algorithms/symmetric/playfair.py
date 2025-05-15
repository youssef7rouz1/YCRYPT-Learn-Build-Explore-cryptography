"""
Playfair cipher implementation with correct encryption and decryption logic.

Features:
- Maps 'J'→'I', preserves spaces.
- Pads repeated letters with 'X' (or final letter if odd length) on encrypt.
- Removes padding on decrypt (eliding inserted 'X' between duplicates and trailing pad).

API:
- encrypt(plaintext: str, key: str) -> str
- decrypt(ciphertext: str, key: str) -> str

Internal helpers:
- _prepare_text: uppercase, map J→I, remove non-letters, record spaces
- _chunk_text: form digraphs with 'X' padding for repeats or odd end
- generate_key_matrix: build 5×5 matrix
- _find: locate character in matrix
- _enc_pair / _dec_pair: encrypt or decrypt one digraph
"""
import re
from typing import List, Tuple

ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
M = 5  # matrix size


def generate_key_matrix(key: str) -> List[List[str]]:
    key = key.upper().replace('J', 'I')
    seen = set()
    seq = []
    for ch in key:
        if ch in ALPHABET and ch not in seen:
            seen.add(ch)
            seq.append(ch)
    for ch in ALPHABET:
        if ch not in seen:
            seq.append(ch)
    return [seq[i*M:(i+1)*M] for i in range(M)]


def _prepare_text(text: str) -> Tuple[str, List[int]]:
    """
    Uppercase, map J→I, remove non-letters, record positions of spaces.
    """
    spaces = [i for i,c in enumerate(text) if c == ' ']
    cleaned = ''.join(c for c in text.replace('J','I') if c.upper() in ALPHABET)
    return cleaned, spaces


def _chunk_text(s: str) -> List[Tuple[str,str]]:
    """
    Split into digraphs, inserting 'X' between identical letters or at end.
    """
    digraphs = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) and s[i+1] != a else 'X'
        digraphs.append((a,b))
        i += 2 if b != 'X' and i+1 < len(s) else 1
    if len(digraphs[-1][1]) == 0:  # odd final
        digraphs[-1] = (digraphs[-1][0], 'X')
    return digraphs


def _find(ch: str, matrix: List[List[str]]) -> Tuple[int,int]:
    for r,row in enumerate(matrix):
        for c,val in enumerate(row):
            if val.lower() == ch.lower():
                return r,c
    raise ValueError(f"{ch} not in matrix")


def _enc_pair(a: str, b: str, mat: List[List[str]]) -> Tuple[str,str]:
    r1,c1 = _find(a, mat)
    r2,c2 = _find(b, mat)
    if r1 == r2:
        return mat[r1][(c1+1)%M], mat[r2][(c2+1)%M]
    if c1 == c2:
        return mat[(r1+1)%M][c1], mat[(r2+1)%M][c2]
    return mat[r1][c2], mat[r2][c1]


def _dec_pair(a: str, b: str, mat: List[List[str]]) -> Tuple[str,str]:
    r1,c1 = _find(a, mat)
    r2,c2 = _find(b, mat)
    if r1 == r2:
        return mat[r1][(c1-1)%M], mat[r2][(c2-1)%M]
    if c1 == c2:
        return mat[(r1-1)%M][c1], mat[(r2-1)%M][c2]
    return mat[r1][c2], mat[r2][c1]


def encrypt(plaintext: str, key: str) -> str:
    mat = generate_key_matrix(key)
    cleaned, spaces = _prepare_text(plaintext)
    digr = _chunk_text(cleaned)
    out = []
    for a,b in digr:
        x,y = _enc_pair(a,b,mat)
        out.extend([x,y])
    for pos in spaces:
        out.insert(pos, ' ')
    return ''.join(out)


def decrypt(ciphertext: str, key: str) -> str:
    mat = generate_key_matrix(key)
    cleaned, spaces = _prepare_text(ciphertext)
    if len(cleaned)%2:
        cleaned += 'X'
    digr = [(cleaned[i], cleaned[i+1]) for i in range(0, len(cleaned), 2)]
    out = []
    for a,b in digr:
        x,y = _dec_pair(a,b,mat)
        out.extend([x,y])
    for pos in spaces:
        out.insert(pos, ' ')
    result = ''.join(out)
    # remove padding X between identical letters and trailing X
    result = re.sub(r'(?<=([A-Z]))X(?=\1)', r'\1', result)
    if result.endswith('X'):
        result = result[:-1]
    return result
print(_chunk_text(_prepare_text(("zez grzkgr rDPZAPkrg " ))))
