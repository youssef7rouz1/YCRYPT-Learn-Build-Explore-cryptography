"""
Columnar Transposition Cipher implementation.


- encrypt(plaintext: str, key: str, pad: str = '_') -> str
- decrypt(ciphertext: str, key: str, pad: str = '_') -> str


- _column_order(key: str) -> List[int]
- encrypt builds a row-wise grid and reads out columns in key order
- decrypt rebuilds columns then reads out row-wise, stripping padding
"""

import math
from typing import List

def _column_order(key: str) -> List[int]:
    """
    Given a key string, return the order in which to read columns.
    E.g. key="HACK" -> letters ['A','C','H','K'] sorted gives order [2,1,0,3]
    """
    uppercase = list(key.upper())
    sorted_key = sorted((ch, idx) for idx, ch in enumerate(uppercase))
    print(sorted_key)
    # map original index to its rank in sorted order
    order=[]
    for i in range(len(key)):
        order.append(0)
    for i in range(len(sorted_key)):
        orig_index=sorted_key[i][1]
        order[orig_index] = i
    
    return order

def encrypt(plaintext: str, key: str, pad: str = '_') -> str:
    """
    Encrypts plaintext with a columnar transposition using the given key.
    Pads empty cells with pad character.
    """
    cols = len(key)
    # remove nothing: we preserve spaces
    msg = list(plaintext)
    # how many rows?
    rows = math.ceil(len(msg) / cols)
    # pad end of message
    fill = rows * cols - len(msg)
    msg.extend(pad * fill)
    # build the grid row-wise
    grid = [ msg[i*cols:(i+1)*cols] for i in range(rows) ]
    # determine read order
    order = _column_order(key)
    # read out columns in increasing rank
    result = []
    for rank in range(cols):
        col_idx = order.index(rank)
        for r in range(rows):
            result.append(grid[r][col_idx])
    return ''.join(result)

def decrypt(ciphertext: str, key: str, pad: str = '_') -> str:
    """
    Decrypts a columnar transposition ciphertext with the given key.
    Strips trailing pad characters.
    """
    cols = len(key)
    rows = math.ceil(len(ciphertext) / cols)
    # determine read order
    order = _column_order(key)
    # how many characters per column? here uniform since we padded on encrypt
    per_col = rows
    # split ciphertext into column chunks in sorted-key order
    cols_data: List[List[str]] = [ [] for _ in range(cols) ]
    idx = 0
    for rank in range(cols):
        col_idx = order.index(rank)
        chunk = list(ciphertext[idx: idx + per_col])
        cols_data[col_idx] = chunk
        idx += per_col
    # read out row-wise
    plain_chars = []
    for r in range(rows):
        for c in range(cols):
            plain_chars.append(cols_data[c][r])
    # strip trailing padding only
    pt = ''.join(plain_chars)
    if pad:
        pt = pt.rstrip(pad)
    return pt

print(encrypt("Geeks for Geeks","HACK"))
print(decrypt('e  kefGsGsrekoe_','HACK'))