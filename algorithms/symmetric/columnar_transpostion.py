import math
from typing import List

def _column_order(key: str) -> List[int]:
    """Compute the order in which to read columns from the key."""
    upper = list(key.upper())
    # Pair each letter with its original index, then sort
    sorted_pairs = sorted((ch, i) for i, ch in enumerate(upper))
    order = [0] * len(key)
    # Assign each original index its rank in the sorted list
    for rank, (_, orig_i) in enumerate(sorted_pairs):
        order[orig_i] = rank
    return order

def encrypt(plaintext: str, key: str, pad: str = '_') -> str:
    """Encrypt by writing text row-wise and reading off columns in key order."""
    cols = len(key)
    chars = list(plaintext)
    rows = math.ceil(len(chars) / cols)
    # Pad to fill the final row
    chars.extend(pad * (rows * cols - len(chars)))
    # Build rows
    grid = [chars[i*cols:(i+1)*cols] for i in range(rows)]
    order = _column_order(key)
    # Read out columns by increasing rank
    result = []
    for rank in range(cols):
        col = order.index(rank)
        for row in grid:
            result.append(row[col])
    return ''.join(result)

def decrypt(ciphertext: str, key: str, pad: str = '_') -> str:
    """Reverse columnar transposition, stripping any padding at the end."""
    cols = len(key)
    rows = math.ceil(len(ciphertext) / cols)
    order = _column_order(key)
    per_col = rows
    # Split the ciphertext into columns according to sorted key order
    cols_data = [[] for _ in range(cols)]
    idx = 0
    for rank in range(cols):
        col = order.index(rank)
        chunk = list(ciphertext[idx:idx + per_col])
        cols_data[col] = chunk
        idx += per_col
    # Reconstruct plaintext row-wise
    plaintext = []
    for r in range(rows):
        for c in range(cols):
            plaintext.append(cols_data[c][r])
    # Remove padding if present
    text = ''.join(plaintext)
    return text.rstrip(pad) if pad else text

if __name__=="__main__":
    print(encrypt("azertyuiop" , "azqsdqsz"))