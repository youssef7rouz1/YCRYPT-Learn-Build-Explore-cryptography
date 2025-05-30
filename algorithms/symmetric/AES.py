import os
from typing import List, Tuple
from utils.AES_constants import S_BOX, INV_S_BOX, RCON
from utils.useful_functions import gf256_mul, pkcs7_pad, pkcs7_unpad, xor_bytes

# AES settings
Nb = 4
BLOCK_SIZE = 16

def _get_aes_params(key: bytes) -> Tuple[int, int]:
    """Determine key schedule words and round count based on key length."""
    length = len(key)
    if length == 16:
        return 4, 10
    if length == 24:
        return 6, 12
    if length == 32:
        return 8, 14
    raise ValueError(f"Invalid AES key length: {length}")

# Core AES operations
gmul = gf256_mul

def sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]

def shift_rows(state: List[List[int]]) -> None:
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

def mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2]           ^ a[3]
        state[1][c] = a[0]           ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        state[2][c] = a[0]           ^ a[1]           ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        state[3][c] = gmul(a[0], 3) ^ a[1]           ^ a[2]           ^ gmul(a[3], 2)

def add_round_key(state: List[List[int]], rk: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] ^= rk[r][c]

# Inverse steps for decryption
def inv_sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]

def inv_shift_rows(state: List[List[int]]) -> None:
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]

def inv_mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gmul(a[0], 0x0e) ^ gmul(a[1], 0x0b) ^ gmul(a[2], 0x0d) ^ gmul(a[3], 0x09)
        state[1][c] = gmul(a[0], 0x09) ^ gmul(a[1], 0x0e) ^ gmul(a[2], 0x0b) ^ gmul(a[3], 0x0d)
        state[2][c] = gmul(a[0], 0x0d) ^ gmul(a[1], 0x09) ^ gmul(a[2], 0x0e) ^ gmul(a[3], 0x0b)
        state[3][c] = gmul(a[0], 0x0b) ^ gmul(a[1], 0x0d) ^ gmul(a[2], 0x09) ^ gmul(a[3], 0x0e)

def _bytes2state(block: bytes) -> List[List[int]]:
    return [[block[c*4 + r] for c in range(4)] for r in range(4)]

def _state2bytes(state: List[List[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))

def key_expansion(key: bytes) -> List[List[List[int]]]:
    """Generate round keys from the original key."""
    Nk, Nr = _get_aes_params(key)
    words = [list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk, Nb*(Nr+1)):
        temp = words[i-1].copy()
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[i//Nk]
        elif Nk > 6 and i % Nk == 4:
            temp = [S_BOX[b] for b in temp]
        words.append([words[i-Nk][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for rnd in range(Nr+1):
        rk = [[words[rnd*4 + c][r] for c in range(4)] for r in range(4)]
        round_keys.append(rk)
    return round_keys

def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt a single 16-byte block."""
    assert len(block) == BLOCK_SIZE, "Block must be 16 bytes"
    Nk, Nr = _get_aes_params(key)
    rk = key_expansion(key)
    state = _bytes2state(block)
    add_round_key(state, rk[0])
    for rnd in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, rk[rnd])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, rk[Nr])
    return _state2bytes(state)

def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt a single 16-byte block."""
    assert len(block) == BLOCK_SIZE, "Block must be 16 bytes"
    Nk, Nr = _get_aes_params(key)
    rk = key_expansion(key)
    state = _bytes2state(block)
    add_round_key(state, rk[Nr])
    for rnd in range(Nr-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, rk[rnd])
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, rk[0])
    return _state2bytes(state)

def encrypt_ecb(plaintext: str, key: str) -> str:
    """AES-ECB mode with PKCS#7 padding."""
    data = pkcs7_pad(plaintext.encode(), BLOCK_SIZE)
    key_b = key.encode()
    ct = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ct.extend(encrypt_block(data[i:i+BLOCK_SIZE], key_b))
    return ct.hex()

def decrypt_ecb(cipher_hex: str, key: str) -> str:
    """AES-ECB decryption and unpadding."""
    data = bytes.fromhex(cipher_hex)
    key_b = key.encode()
    pt = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        pt.extend(decrypt_block(data[i:i+BLOCK_SIZE], key_b))
    return pkcs7_unpad(bytes(pt)).decode('utf-8', errors='ignore')

def _parse_iv(iv_str: str) -> bytes:
    """Accepts hex or ASCII IV, or generates a random IV if blank."""
    s = iv_str.strip()
    if not s:
        return os.urandom(BLOCK_SIZE)
    if len(s) == BLOCK_SIZE*2 and all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    b = s.encode()
    if len(b) == BLOCK_SIZE:
        return b
    raise ValueError("IV must be 16 ASCII chars or 32 hex digits")

def encrypt_cbc(plaintext: str, key: str, iv_str: str = "") -> str:
    """AES-CBC with PKCS#7 padding. Prepends IV if not provided."""
    data = pkcs7_pad(plaintext.encode(), BLOCK_SIZE)
    key_b = key.encode()
    iv = _parse_iv(iv_str)
    prev = iv
    ct = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        x = xor_bytes(data[i:i+BLOCK_SIZE], prev)
        c = encrypt_block(x, key_b)
        ct.extend(c)
        prev = c
    return (iv + ct).hex() if not iv_str else ct.hex()

def decrypt_cbc(cipher_hex: str, key: str, iv_str: str = "") -> str:
    """AES-CBC decryption, handles attached or separate IV."""
    data = bytes.fromhex(cipher_hex)
    key_b = key.encode()
    if iv_str:
        iv = _parse_iv(iv_str)
        blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    else:
        iv = data[:BLOCK_SIZE]
        blocks = [data[i:i+BLOCK_SIZE] for i in range(BLOCK_SIZE, len(data), BLOCK_SIZE)]
    pt = bytearray()
    prev = iv
    for blk in blocks:
        db = decrypt_block(blk, key_b)
        pt.extend(xor_bytes(db, prev))
        prev = blk
    return pkcs7_unpad(bytes(pt)).decode('utf-8', errors='ignore')

def encrypt_ctr(plaintext: str, key: str, nonce_str: str = "") -> str:
    """AES-CTR mode. XORs plaintext with keystream blocks."""
    data = plaintext.encode()
    key_b = key.encode()
    ctr = bytearray(_parse_iv(nonce_str))
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ks = encrypt_block(bytes(ctr), key_b)
        blk = data[i:i+BLOCK_SIZE]
        for j, b in enumerate(blk):
            out.append(b ^ ks[j])
        # increment big-endian counter
        for k in range(BLOCK_SIZE-1, -1, -1):
            ctr[k] = (ctr[k] + 1) & 0xFF
            if ctr[k] != 0:
                break
    return out.hex()

def decrypt_ctr(ciphertext: str, key: str, nonce_str: str = "") -> str:
    """AES-CTR decryption (same as encryption)."""
    data = bytes.fromhex(ciphertext)
    key_b = key.encode()
    ctr = bytearray(_parse_iv(nonce_str))
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ks = encrypt_block(bytes(ctr), key_b)
        blk = data[i:i+BLOCK_SIZE]
        for j, b in enumerate(blk):
            out.append(b ^ ks[j])
        for k in range(BLOCK_SIZE-1, -1, -1):
            ctr[k] = (ctr[k] + 1) & 0xFF
            if ctr[k] != 0:
                break
    return out.decode('utf-8')
