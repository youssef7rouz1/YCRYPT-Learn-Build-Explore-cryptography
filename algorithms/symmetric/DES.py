from utils.useful_functions import *
from utils.DES_constants import (
    initial_key_permutation,
    key_shift_sizes,
    sub_key_permuation,
    initial_message_permutation,
    message_expansion,
    half_block_permuation,
    final_message_permutation,
    S_BOXES,
)




# Rotate-left shift on bit-string



def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)

# Generate 16 round keys (48-bit) from 64-bit hex key

def generate_round_keys(key_hex):
    key_bits = hex_to_bits(key_hex)
    permuted = permute(key_bits, initial_key_permutation)
    c, d = permuted[:28], permuted[28:]
    round_keys = []
    for shift in key_shift_sizes:
        c = left_shift(c, shift)
        d = left_shift(d, shift)
        combined = c + d
        subkey = permute(combined, sub_key_permuation)
        round_keys.append(subkey)
    return round_keys

# DES f-function: expansion, key mixing, S-box, P-permute

def sbox_substitution(bits48):
    out = []
    for i in range(8):
        block = bits48[i*6:(i+1)*6]
        row = int(block[0] + block[-1], 2)
        col = int(block[1:5], 2)
        val = S_BOXES[i][row][col]
        out.append(format(val, '04b'))
    return ''.join(out)


def f_function(r, subkey):
    e = permute(r, message_expansion)
    x = xor_bits(e, subkey)
    s = sbox_substitution(x)
    return permute(s, half_block_permuation)

# Encrypt one 64-bit block (16 hex chars)

def encrypt_block(pt_hex, round_keys):
    bits = permute(hex_to_bits(pt_hex), initial_message_permutation)
    l, r = bits[:32], bits[32:]
    for k in round_keys:
        l, r = r, xor_bits(l, f_function(r, k))
    pre = r + l
    return bits_to_hex(permute(pre, final_message_permutation))

# Decrypt one 64-bit block by reversing subkeys

def decrypt_block(ct_hex, round_keys):
    return encrypt_block(ct_hex, list(reversed(round_keys)))

# High-level ECB encrypt: UTF-8 plaintext + key → hex ciphertext

def encrypt_ecb(plaintext, key_str):
    key_bytes = utf8_to_bytes(key_str)[:8].ljust(8, b'\x00')
    key_hex = key_bytes.hex().upper()
    pt_padded = pad_bytes(utf8_to_bytes(plaintext))
    pt_hex = pt_padded.hex().upper()
    rk = generate_round_keys(key_hex)
    out=[]
    for i in range(0,len(pt_hex),16):
        out.append(encrypt_block(pt_hex[i:i+16],rk))

    return ''.join(
       out
    )

# High-level ECB decrypt: hex ciphertext + key → UTF-8 plaintext

def decrypt_ecb(cipher_hex, key_str):
    key_bytes = utf8_to_bytes(key_str)[:8].ljust(8, b'\x00')
    key_hex = key_bytes.hex().upper()
    rk = generate_round_keys(key_hex)
    hex_blocks = [cipher_hex[i:i+16] for i in range(0, len(cipher_hex), 16)]
    pt_hex = ''.join(decrypt_block(b, rk) for b in hex_blocks)
    data = hex_to_bytes(pt_hex)
    pad_len = data[-1]
    raw = data[:-pad_len]
    return bytes_to_utf8(raw)



# ------------------------------------------------------------------
# High-level CBC functions
# ------------------------------------------------------------------

def encrypt_cbc(plaintext: str, key_str: str, iv_hex: str) -> str:
    """
    DES-CBC encrypt: UTF-8 plaintext + UTF-8 key + 16-hex-digit IV
    returns ciphertext as hex string.
    """
    # 1) Prepare key schedule (8-byte key, PKCS#5 style)
    key_bytes = utf8_to_bytes(key_str)[:8].ljust(8, b'\x00')
    key_hex   = key_bytes.hex().upper()
    rk        = generate_round_keys(key_hex)

    # 2) Pad plaintext to 8-byte boundary & hex-encode
    pt_bytes  = utf8_to_bytes(plaintext)
    pt_padded = pad_bytes(pt_bytes)
    pt_hex    = pt_padded.hex().upper()

    # 3) CBC chain: XOR-then-ECB
    prev = iv_hex.upper()
    ct_blocks = []
    for i in range(0, len(pt_hex), 16):
        block_hex = pt_hex[i:i+16]
        # bitwise XOR with previous

        xored_plain_and_prev_cipher = bits_to_hex(xor_bits(hex_to_bits(prev),hex_to_bits(block_hex)))
        cipher_block_after_xor = encrypt_block(xored_plain_and_prev_cipher, rk)
        ct_blocks.append(cipher_block_after_xor)
        prev = cipher_block_after_xor

    return ''.join(ct_blocks)


def decrypt_cbc(cipher_hex: str, key_str: str, iv_hex: str) -> str:
    """
    DES-CBC decrypt: hex ciphertext + UTF-8 key + 16-hex-digit IV
    returns UTF-8 plaintext.
    """
    # 1) Prepare key schedule
    key_bytes = utf8_to_bytes(key_str)[:8].ljust(8, b'\x00')
    key_hex   = key_bytes.hex().upper()
    rk        = generate_round_keys(key_hex)

    # 2) Decrypt blocks and un-XOR
    prev = iv_hex.upper()
    pt_hex_blocks = []
    for i in range(0, len(cipher_hex), 16):
        cblk = cipher_hex[i:i+16]
        # ECB decrypt
        p_xored = decrypt_block(cblk, rk)
        # remove the CBC XOR
        pblk_hex = bits_to_hex(
            xor_bits(
                hex_to_bits(p_xored),
                hex_to_bits(prev)
            )
        )
        pt_hex_blocks.append(pblk_hex)
        prev = cblk

    joined_hex = ''.join(pt_hex_blocks)
    data = hex_to_bytes(joined_hex)

    # 3) Strip PKCS#5 padding and decode UTF-8
    pad_len = data[-1]
    raw     = data[:-pad_len]
    return bytes_to_utf8(raw)


# Example usage
def triple_des_encrypt_ecb(plaintext: str, key_str: str) -> str:
    """
    3DES-ECB encrypt (EDE):
      C = E_{K3}( D_{K2}( E_{K1}(P) ) )
    Takes a UTF-8 plaintext and a UTF-8 key_str (will be truncated/padded
    to 24 bytes), returns hex ciphertext.
    """
    # 1) Derive three 8-byte keys from the master key_str
    master = key_str.encode('utf-8')[:24].ljust(24, b'\x00')
    K1, K2, K3 = master[:8], master[8:16], master[16:24]

    # 2) Build DES subkey schedules for each
    RK1 = generate_round_keys(K1.hex().upper())
    RK2 = generate_round_keys(K2.hex().upper())
    RK3 = generate_round_keys(K3.hex().upper())

    # 3) Pad once, then hex-encode the whole plaintext
    pt_bytes = pad_bytes(plaintext.encode('utf-8'))
    pt_hex   = pt_bytes.hex().upper()

    # 4) Process each 16-hex-char (64-bit) block with EDE
    ct_chunks = []
    for i in range(0, len(pt_hex), 16):
        blk = pt_hex[i:i+16]
        x1  = encrypt_block(blk, RK1)
        x2  = decrypt_block(x1, RK2)
        c   = encrypt_block(x2, RK3)
        ct_chunks.append(c)

    return ''.join(ct_chunks)





def triple_des_decrypt_ecb(cipher_hex: str, key_str: str) -> str:
    """
    3DES-ECB decrypt (DED):
      P = D_{K1}( E_{K2}( D_{K3}(C) ) )
    Takes hex ciphertext and UTF-8 key_str, returns UTF-8 plaintext.
    """
    # 1) Same key splitting
    master = key_str.encode('utf-8')[:24].ljust(24, b'\x00')
    K1, K2, K3 = master[:8], master[8:16], master[16:24]

    # 2) Same subkey schedules
    RK1 = generate_round_keys(K1.hex().upper())
    RK2 = generate_round_keys(K2.hex().upper())
    RK3 = generate_round_keys(K3.hex().upper())

    # 3) Process each 16-hex-char block with DED
    pt_hex_chunks = []
    for i in range(0, len(cipher_hex), 16):
        cblk = cipher_hex[i:i+16]
        y1   = decrypt_block(cblk, RK3)
        y2   = encrypt_block(y1, RK2)
        pblk = decrypt_block(y2, RK1)
        pt_hex_chunks.append(pblk)

    # 4) Join, unhex, strip padding, decode UTF-8
    joined_hex = ''.join(pt_hex_chunks)
    data       = hex_to_bytes(joined_hex)
    pad_len    = data[-1]
    raw        = data[:-pad_len]
    return bytes_to_utf8(raw)



def triple_des_encrypt_cbc(plaintext: str, key_str: str, iv: str) -> str:
    """
    3DES-CBC encrypt (EDE + CBC):
      C_i = E3( D2( E1( P_i + C_{i-1} ) ) ),  C_0 = IV
    Returns hex ciphertext.
    """
    # 1) Split master key into three 8-byte keys
    master = key_str.encode('utf-8')[:24].ljust(24, b'\x00')
    K1, K2, K3 = master[:8], master[8:16], master[16:24]

    # 2) Build DES subkey schedules
    RK1 = generate_round_keys(K1.hex().upper())
    RK2 = generate_round_keys(K2.hex().upper())
    RK3 = generate_round_keys(K3.hex().upper())

    # 3) Pad once, then hex-encode plaintext
    pt_bytes = pad_bytes(plaintext.encode('utf-8'))
    pt_hex   = pt_bytes.hex().upper()
    iv_hex=utf8_to_hex(iv)
    # 4) CBC chain with 3DES EDE per block
    prev = iv_hex.upper()
    ct_chunks = []
    for i in range(0, len(pt_hex), 16):
        blk = pt_hex[i:i+16]
        # XOR plaintext block with previous ciphertext (or IV)
        xored = bits_to_hex(xor_bits(hex_to_bits(blk), hex_to_bits(prev)))
        # 3DES EDE
        y1 = encrypt_block(xored, RK1)
        y2 = decrypt_block(y1, RK2)
        c  = encrypt_block(y2, RK3)
        ct_chunks.append(c)
        prev = c

    return ''.join(ct_chunks)


def triple_des_decrypt_cbc(cipher_hex: str, key_str: str, iv: str) -> str:
    """
    3DES-CBC decrypt (DED + CBC):
      P_i = D1( E2( D3( C_i ) ) ) + C_{i-1},  C_0 = IV
    Returns UTF-8 plaintext.
    """
    # 1) Split master key
    master = key_str.encode('utf-8')[:24].ljust(24, b'\x00')
    K1, K2, K3 = master[:8], master[8:16], master[16:24]

    # 2) Build DES schedules
    RK1 = generate_round_keys(K1.hex().upper())
    RK2 = generate_round_keys(K2.hex().upper())
    RK3 = generate_round_keys(K3.hex().upper())

    # 3) CBC de-chain with 3DES DED per block
    iv_hex=utf8_to_hex(iv)
    prev = iv_hex.upper()
    pt_hex_chunks = []
    for i in range(0, len(cipher_hex), 16):
        cblk = cipher_hex[i:i+16]
        # 3DES DED
        y1    = decrypt_block(cblk, RK3)
        y2    = encrypt_block(y1, RK2)
        p_xor = decrypt_block(y2, RK1)
        # XOR with previous ciphertext (or IV)
        p_blk = bits_to_hex(xor_bits(hex_to_bits(p_xor), hex_to_bits(prev)))
        pt_hex_chunks.append(p_blk)
        prev = cblk

    # 4) Unhex, strip padding, decode UTF-8
    joined_hex = ''.join(pt_hex_chunks)
    data       = hex_to_bytes(joined_hex)
    pad_len    = data[-1]
    raw        = data[:-pad_len]
    return bytes_to_utf8(raw)



