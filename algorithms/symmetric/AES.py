import os
from typing import List
from utils.AES_constants import S_BOX, INV_S_BOX, RCON
from utils.useful_functions import (
    gf256_mul, pkcs7_pad, pkcs7_unpad, xor_bytes
)

# AES block size and state dimensions\BLOCK_SIZE = 16
Nb = 4  # always 4 words (16 bytes)
BLOCK_SIZE=16

def _get_aes_params(key: bytes) -> tuple[int,int]:
    """
    Derive Nk (key words) and Nr (rounds) from key length.
    """
    L = len(key)
    if L == 16:
        return 4, 10
    elif L == 24:
        return 6, 12
    elif L == 32:
        return 8, 14
    else:
        raise ValueError("Invalid AES key length: %d" % L)

# Core AES primitives
gmul = gf256_mul  # GF(2^8) multiply

def sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]

def shift_rows(state: List[List[int]]) -> None:
    for r in range(1,4):
        state[r] = state[r][r:] + state[r][:r]

def mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gmul(a[0],2) ^ gmul(a[1],3) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ gmul(a[1],2) ^ gmul(a[2],3) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ gmul(a[2],2) ^ gmul(a[3],3)
        state[3][c] = gmul(a[0],3) ^ a[1] ^ a[2] ^ gmul(a[3],2)

def add_round_key(state: List[List[int]], rk: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] ^= rk[r][c]

# Inverse primitives for decryption
def inv_sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]

def inv_shift_rows(state: List[List[int]]) -> None:
    for r in range(1,4):
        state[r] = state[r][-r:] + state[r][:-r]

def inv_mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gmul(a[0],0x0e) ^ gmul(a[1],0x0b) ^ gmul(a[2],0x0d) ^ gmul(a[3],0x09)
        state[1][c] = gmul(a[0],0x09) ^ gmul(a[1],0x0e) ^ gmul(a[2],0x0b) ^ gmul(a[3],0x0d)
        state[2][c] = gmul(a[0],0x0d) ^ gmul(a[1],0x09) ^ gmul(a[2],0x0e) ^ gmul(a[3],0x0b)
        state[3][c] = gmul(a[0],0x0b) ^ gmul(a[1],0x0d) ^ gmul(a[2],0x09) ^ gmul(a[3],0x0e)

# State <-> bytes converters
def _bytes2state(block: bytes) -> List[List[int]]:
    return [[block[c*4 + r] for c in range(4)] for r in range(4)]

def _state2bytes(state: List[List[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))

# Key schedule (generic for 128/192/256)
def key_expansion(key: bytes) -> List[List[List[int]]]:
    Nk, Nr = _get_aes_params(key)
    # initial 4*Nk bytes -> words
    words: List[List[int]] = [list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk, Nb*(Nr+1)):
        temp = words[i-1].copy()
        if i % Nk == 0:
            # RotWord + SubBytes + RCON
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[i//Nk]
        elif Nk > 6 and i % Nk == 4:
            # extra SubBytes step for AES-256
            temp = [S_BOX[b] for b in temp]
        words.append([words[i-Nk][j] ^ temp[j] for j in range(4)])
    # collect round keys
    round_keys: List[List[List[int]]] = []
    for rnd in range(Nr+1):
        rk = [[0]*4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                rk[r][c] = words[rnd*4 + c][r]
        round_keys.append(rk)
    return round_keys

# Block encrypt/decrypt

def encrypt_block(block: bytes, key: bytes) -> bytes:
    assert len(block)==BLOCK_SIZE, "Block must be 16 bytes"
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
    assert len(block)==BLOCK_SIZE, "Block must be 16 bytes"
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

# — Modes: ECB, CBC, CTR —

def encrypt_ecb(plaintext: str, key: str) -> str:
    data = pkcs7_pad(plaintext.encode(), BLOCK_SIZE)
    key_b = key.encode()
    ct = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ct.extend(encrypt_block(data[i:i+BLOCK_SIZE], key_b))
    return ct.hex()

def decrypt_ecb(cipher_hex: str, key: str) -> str:
    data = bytes.fromhex(cipher_hex)
    key_b = key.encode()
    pt = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        pt.extend(decrypt_block(data[i:i+BLOCK_SIZE], key_b))
    return pkcs7_unpad(bytes(pt)).decode('utf-8', errors='ignore')


def _parse_iv(iv_str: str) -> bytes:
    s = iv_str.strip()
    if not s:
        return os.urandom(BLOCK_SIZE)
    if len(s)==BLOCK_SIZE*2 and all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    b = s.encode()
    if len(b)==BLOCK_SIZE:
        return b
    raise ValueError("IV must be 16 ASCII chars or 32 hex digits")

def encrypt_cbc(plaintext: str, key: str, iv_str: str="") -> str:
    data = pkcs7_pad(plaintext.encode(), BLOCK_SIZE)
    key_b = key.encode()
    iv = _parse_iv(iv_str)
    prev = iv
    ct = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        blk = data[i:i+BLOCK_SIZE]
        x = xor_bytes(blk, prev)
        c = encrypt_block(x, key_b)
        ct.extend(c)
        prev = c
    return (iv+ct).hex() if not iv_str else ct.hex()

def decrypt_cbc(cipher_hex: str, key: str, iv_str: str="") -> str:
    data = bytes.fromhex(cipher_hex)
    key_b = key.encode()
    if iv_str:
        iv = _parse_iv(iv_str)
        ct_blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    else:
        iv = data[:BLOCK_SIZE]
        ct_blocks = [data[i:i+BLOCK_SIZE] for i in range(BLOCK_SIZE, len(data), BLOCK_SIZE)]
    pt = bytearray()
    prev = iv
    for blk in ct_blocks:
        db = decrypt_block(blk, key_b)
        pt.extend(xor_bytes(db, prev))
        prev = blk
    return pkcs7_unpad(bytes(pt)).decode('utf-8', errors='ignore')


def _parse_nonce(nonce_str: str) -> bytes:
    # same as parse_iv but generic
    return _parse_iv(nonce_str)

def _inc_counter(counter: bytearray):
    for i in range(len(counter)-1, -1, -1):
        counter[i] = (counter[i]+1)&0xFF
        if counter[i]!=0:
            break

def encrypt_ctr(plaintext: str, key: str, nonce_str: str="") -> str:
    data = plaintext.encode()
    key_b = key.encode()
    ctr = bytearray(_parse_nonce(nonce_str))
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ks = encrypt_block(bytes(ctr), key_b)
        blk = data[i:i+BLOCK_SIZE]
        for j,b in enumerate(blk): out.append(b ^ ks[j])
        _inc_counter(ctr)
    return out.hex()

def decrypt_ctr(ciphertext: str, key: str, nonce_str: str="") -> str:
    data = bytes.fromhex(ciphertext)
    key_b = key.encode()
    ctr = bytearray(_parse_nonce(nonce_str))
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ks = encrypt_block(bytes(ctr), key_b)
        blk = data[i:i+BLOCK_SIZE]
        for j,b in enumerate(blk): out.append(b ^ ks[j])
        _inc_counter(ctr)
    return out.decode('utf-8')


