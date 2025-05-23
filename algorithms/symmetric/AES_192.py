
import os
import string
from typing import List
from utils.AES_constants import S_BOX , INV_S_BOX , RCON

# ——— AES-128 PARAMETERS ——————————————————————————————————————
Nb = 4    # state width in 32-bit words
Nk = 6    # key length in 32-bit words
Nr = 12   # number of rounds
BLOCK_SIZE = 16

# ——— Load the constans S box , RCON ————————————————————————————————————


# ——— Core aes fucntions ————————————————————————————————————

def gmul(a: int, b: int) -> int: #mutliplication in Galois Field
    p = 0
    for _ in range(8): # no need for counter , we only want to repeat this 8 times
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if hi else 0)
        b >>= 1
    return p

def sub_bytes(state: List[List[int]]) -> None:  #first step in AES : SubBytes
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]

def shift_rows(state: List[List[int]]) -> None: # second step : shift rows
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

def mix_columns(state: List[List[int]]) -> None:  # third step : mixcolumns
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gmul(a[0],2) ^ gmul(a[1],3) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ gmul(a[1],2) ^ gmul(a[2],3) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ gmul(a[2],2) ^ gmul(a[3],3)
        state[3][c] = gmul(a[0],3) ^ a[1] ^ a[2] ^ gmul(a[3],2)

def add_round_key(state: List[List[int]], rk: List[List[int]]) -> None: #fourth step : xor the state with the round key
    for i in range(4):
        for j in range(4):
            state[i][j] ^= rk[i][j]




############ Decryption useful functions ############### 

def inv_sub_bytes(state: List[List[int]]) -> None: 
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_S_BOX[state[i][j]]

def inv_shift_rows(state: List[List[int]]) -> None:
    # rotate right
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]

def inv_mix_columns(state: List[List[int]]) -> None:
    # AES inverse MixColumns matrix: [0e 0b 0d 09; 09 0e 0b 0d; …]
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gmul(a[0],0x0e) ^ gmul(a[1],0x0b) ^ gmul(a[2],0x0d) ^ gmul(a[3],0x09)
        state[1][c] = gmul(a[0],0x09) ^ gmul(a[1],0x0e) ^ gmul(a[2],0x0b) ^ gmul(a[3],0x0d)
        state[2][c] = gmul(a[0],0x0d) ^ gmul(a[1],0x09) ^ gmul(a[2],0x0e) ^ gmul(a[3],0x0b)
        state[3][c] = gmul(a[0],0x0b) ^ gmul(a[1],0x0d) ^ gmul(a[2],0x09) ^ gmul(a[3],0x0e)




def unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """AES-128 single-block decryption."""
    assert len(block) == 16 and len(key) == 24
    # expand key
    rk = key_expansion(key)
    # state
    state = _bytes2state(block)
    # initial round key
    add_round_key(state, rk[Nr])
    # main rounds
    for rnd in range(Nr-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, rk[rnd])
        inv_mix_columns(state)
    # final
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, rk[0])
    return _state2bytes(state)

# ——— Useful functions ——————————————————————————————————————



def key_expansion(key: bytes) -> List[List[List[int]]]: # Key schedule algorithm
    words = [list(key[i:i+4]) for i in range(0, 4*Nk, 4)]
    for i in range(Nk, Nb*(Nr+1)):
        temp = words[i-1].copy()
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[i//Nk]
        words.append([words[i-Nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for rnd in range(Nr+1):
        mat = [[0]*4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                mat[r][c] = words[rnd*4 + c][r]
        round_keys.append(mat)
    return round_keys

# ——— BLOCK ENCRYPTION ——————————————————————————————————————

def _bytes2state(block: bytes) -> List[List[int]]:
    return [[block[i+4*j] for j in range(4)] for i in range(4)]

def _state2bytes(state: List[List[int]]) -> bytes:
    return bytes(state[i][j] for j in range(4) for i in range(4))

def encrypt_block(block: bytes, key: bytes) -> bytes:
    assert len(block) == 16 and len(key) == 24
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

# ——— ECB MODE & PKCS#7 PADDING ——————————————————————————————————


def pad_pkcs7(data: bytes) -> bytes: #padding is required if size of message is not a multiple of block size
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def _parse_iv(iv_str: str) -> bytes:  # the initilization vector used in cbc mode
    s = iv_str.strip()
    if not s:
        return os.urandom(BLOCK_SIZE)
    # hex IV?
    if len(s) == BLOCK_SIZE*2 and all(c in string.hexdigits for c in s):
        return bytes.fromhex(s)
    # ascii IV?
    b = s.encode('utf-8')
    if len(b) == BLOCK_SIZE:
        return b
    raise ValueError("IV must be 16 ASCII chars or 32 hex digits, or empty")


def encrypt_ecb(plaintext: str, key: str) -> str: # Encryption using ecb mode , ecb mode is known to be vulnerable , refer to cbc mode
    data = pad_pkcs7(plaintext.encode('utf-8'))
    k = key.encode('utf-8')
    if len(k) != 24:
        raise ValueError("Key must be exactly 24 characters")
    ct = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ct.extend(encrypt_block(data[i:i+BLOCK_SIZE], k))
    return ct.hex()



def encrypt_cbc(plaintext: str, key: str, iv_str: str = "") -> str: # AES encryption with CBC mode
    data = pad_pkcs7(plaintext.encode('utf-8'))
    k = key.encode('utf-8')
    if len(k) != 24:
        raise ValueError("Key must be exactly 24 characters")
    iv = _parse_iv(iv_str)
    prefix = not iv_str  # only prefix if auto-generated
    prev = iv
    ct = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        x = bytes(a ^ b for a, b in zip(block, prev))
        c = encrypt_block(x, k)
        ct.extend(c)
        prev = c
    out = (iv + ct).hex() if prefix else ct.hex()
    return out







def decrypt_ecb(cipher_hex: str, key: str) -> str:
    data = bytes.fromhex(cipher_hex)
    k = key.encode('utf-8')
    if len(k) != 24:
        raise ValueError("Key must be exactly 24 characters")
    pt = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        pt.extend(decrypt_block(data[i:i+BLOCK_SIZE], k))
    return unpad_pkcs7(bytes(pt)).decode('utf-8', errors='ignore')








def decrypt_cbc(cipher_hex: str, key: str, iv_str: str = "") -> str:
    cdata = bytes.fromhex(cipher_hex)
    k = key.encode('utf-8')
    if len(k) != 24:
        raise ValueError("Key must be exactly 24 characters")

    # on utilise _parse_iv pour accepter IV hex ou ASCII
    iv = _parse_iv(iv_str)

    # découpe des blocs : si iv_str est fourni, cdata ne contient QUE les blocs chiffrés ;
    # sinon le premier bloc est l’IV
    if iv_str:
        ct_blocks = [cdata[i:i+BLOCK_SIZE] for i in range(0, len(cdata), BLOCK_SIZE)]
    else:
        iv = cdata[:BLOCK_SIZE]
        ct_blocks = [cdata[i:i+BLOCK_SIZE] for i in range(BLOCK_SIZE, len(cdata), BLOCK_SIZE)]

    pt = bytearray()
    prev = iv
    for blk in ct_blocks:
        db = decrypt_block(blk, k)
        # XOR avec le vecteur précédent (ou IV)
        pt.extend(bytes(a ^ b for a, b in zip(db, prev)))
        prev = blk

    return unpad_pkcs7(bytes(pt)).decode('utf-8', errors='ignore')





def _parse_nonce(iv_str: str) -> bytes:  
    s = iv_str.strip()
    if not s:
        return os.urandom(BLOCK_SIZE)
    # hex IV?
    if len(s) == BLOCK_SIZE*2 and all(c in string.hexdigits for c in s):
        return bytes.fromhex(s)
    # ascii IV?
    b = s.encode('utf-8')
    if len(b) == BLOCK_SIZE:
        return b
    raise ValueError("IV must be 16 ASCII chars or 32 hex digits, or empty")

def _inc_counter(counter: bytearray):
    for i in range(len(counter)-1, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i]:
            break

def encrypt_ctr(plaintext: str, key: str, nonce_str: str = "") -> str:
    data = plaintext.encode('utf-8')
    k    = key.encode('utf-8')
    if len(k) !=24:
        raise ValueError("Key must be 24 bytes")
    ctr = bytearray(_parse_nonce(nonce_str))   # your 16-byte parser
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        keystream = encrypt_block(bytes(ctr), k)
        block = data[i:i+BLOCK_SIZE]
        for j, b in enumerate(block):
            out.append(b ^ keystream[j])
        _inc_counter(ctr)
    return out.hex()

decrypt_ctr=encrypt_ctr
def decrypt_ctr(ciphertext: str, key: str, nonce_str: str = "") -> str:
    data = bytes.fromhex(ciphertext)
    k    = key.encode('utf-8')
    if len(k) !=24:
        raise ValueError("Key must be 24 bytes")
    ctr = bytearray(_parse_nonce(nonce_str))   
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        keystream = encrypt_block(bytes(ctr), k)
        block = data[i:i+BLOCK_SIZE]
        for j, b in enumerate(block):
            out.append(b ^ keystream[j])
        _inc_counter(ctr)
    return out.decode('utf-8')




