
import os
import string
from typing import List


# ——— AES-128 PARAMETERS ——————————————————————————————————————
Nb = 4    # state width in 32-bit words
Nk = 4    # key length in 32-bit words
Nr = 10   # number of rounds
BLOCK_SIZE = 16





S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]


INV_S_BOX =[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]


RCON = [0x00, 0x01,0x02,0x04,0x08, 0x10,0x20,0x40,0x80,0x1B,0x36]

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
    assert len(block) == 16 and len(key) == 16
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
    assert len(block) == 16 and len(key) == 16
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
    if len(k) != 16:
        raise ValueError("Key must be exactly 16 characters")
    ct = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        ct.extend(encrypt_block(data[i:i+BLOCK_SIZE], k))
    return ct.hex()



def encrypt_cbc(plaintext: str, key: str, iv_str: str = "") -> str: # AES encryption with CBC mode
    data = pad_pkcs7(plaintext.encode('utf-8'))
    k = key.encode('utf-8')
    if len(k) != 16:
        raise ValueError("Key must be exactly 16 characters")
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
    if len(k) != 16:
        raise ValueError("Key must be exactly 16 characters")
    pt = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        pt.extend(decrypt_block(data[i:i+BLOCK_SIZE], k))
    return unpad_pkcs7(bytes(pt)).decode('utf-8', errors='ignore')





def decrypt_cbc(cipher_hex: str, key: str, iv_str: str = "") -> str:
    cdata = bytes.fromhex(cipher_hex)
    k = key.encode('utf-8')
    if len(k) != 16:
        raise ValueError("Key must be exactly 16 characters")

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
    if len(k) !=16:
        raise ValueError("Key must be 16 bytes")
    ctr = bytearray(_parse_nonce(nonce_str))   # your 16-byte parser
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        keystream = encrypt_block(bytes(ctr), k)
        block = data[i:i+BLOCK_SIZE]
        for j, b in enumerate(block):
            out.append(b ^ keystream[j])
        _inc_counter(ctr)
    return out.hex()


def decrypt_ctr(ciphertext: str, key: str, nonce_str: str = "") -> str:
    data = bytes.fromhex(ciphertext)
    k    = key.encode('utf-8')
    if len(k) !=16:
        raise ValueError("Key must be 16 bytes")
    ctr = bytearray(_parse_nonce(nonce_str))   
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        keystream = encrypt_block(bytes(ctr), k)
        block = data[i:i+BLOCK_SIZE]
        for j, b in enumerate(block):
            out.append(b ^ keystream[j])
        _inc_counter(ctr)
    return out.decode('utf-8')


