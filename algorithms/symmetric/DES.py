from utils.useful_functions import *
from utils.DES_constants import (
    initial_key_permutation, key_shift_sizes, sub_key_permuation,
    initial_message_permutation, message_expansion,
    half_block_permuation, final_message_permutation, S_BOXES,
)

def permute(bits: str, table: list[int]) -> str:
    # Apply a fixed permutation table to a bitstring
    return ''.join(bits[i - 1] for i in table)

def generate_round_keys(key_hex: str) -> list[str]:
    # Turn a 64-bit key into 16 subkeys for the Feistel rounds
    key_bits = hex_to_bits(key_hex)
    permuted = permute(key_bits, initial_key_permutation)
    c, d = permuted[:28], permuted[28:]
    round_keys = []
    for shift in key_shift_sizes:
        c, d = left_shift(c, shift), left_shift(d, shift)
        combined = c + d
        round_keys.append(permute(combined, sub_key_permuation))
    return round_keys

def sbox_substitution(bits48: str) -> str:
    # Nonlinear S-Box layer over eight 6-bit chunks
    out = []
    for i in range(8):
        chunk = bits48[i*6:(i+1)*6]
        row, col = int(chunk[0] + chunk[-1], 2), int(chunk[1:5], 2)
        out.append(format(S_BOXES[i][row][col], '04b'))
    return ''.join(out)

def f_function(r: str, subkey: str) -> str:
    # Core DES round function: expand, mix with key, substitute, permute
    expanded = permute(r, message_expansion)
    mixed = xor_bits(expanded, subkey)
    substituted = sbox_substitution(mixed)
    return permute(substituted, half_block_permuation)

def encrypt_block(pt_hex: str, round_keys: list[str]) -> str:
    # Encrypt one 64-bit block under DES initial/final perms
    bits = permute(hex_to_bits(pt_hex), initial_message_permutation)
    left, right = bits[:32], bits[32:]
    for k in round_keys:
        left, right = right, xor_bits(left, f_function(right, k))
    preoutput = right + left
    return bits_to_hex(permute(preoutput, final_message_permutation))

def decrypt_block(ct_hex: str, round_keys: list[str]) -> str:
    # Reverse the key schedule for decryption
    return encrypt_block(ct_hex, list(reversed(round_keys)))

def encrypt_ecb(plaintext: str, key_str: str) -> str:
    # ECB mode: pad, split, encrypt each block
    key_bytes = utf8_to_bytes(key_str)[:8].ljust(8, b'\x00')
    key_hex = key_bytes.hex().upper()
    padded = pad_bytes(utf8_to_bytes(plaintext))
    pt_hex = padded.hex().upper()
    keys = generate_round_keys(key_hex)
    ciphertext = [encrypt_block(pt_hex[i:i+16], keys) for i in range(0, len(pt_hex), 16)]
    return ''.join(ciphertext)

def decrypt_ecb(cipher_hex: str, key_str: str) -> str:
    # ECB decrypt and strip padding
    key_bytes = utf8_to_bytes(key_str)[:8].ljust(8, b'\x00')
    keys = generate_round_keys(key_bytes.hex().upper())
    blocks = [cipher_hex[i:i+16] for i in range(0, len(cipher_hex), 16)]
    pt_hex = ''.join(decrypt_block(b, keys) for b in blocks)
    data = hex_to_bytes(pt_hex)
    pad_len = data[-1]
    return bytes_to_utf8(data[:-pad_len])

def encrypt_cbc(plaintext: str, key_str: str, iv_hex: str) -> str:
    # CBC mode: chain XOR+ECB, using given IV
    key_bytes = utf8_to_bytes(key_str)[:8].ljust(8, b'\x00')
    keys = generate_round_keys(key_bytes.hex().upper())
    padded = pad_bytes(utf8_to_bytes(plaintext))
    pt_hex = padded.hex().upper()
    prev = iv_hex.upper()
    ct_blocks = []
    for i in range(0, len(pt_hex), 16):
        chunk = pt_hex[i:i+16]
        xored = bits_to_hex(xor_bits(hex_to_bits(prev), hex_to_bits(chunk)))
        ciphered = encrypt_block(xored, keys)
        ct_blocks.append(ciphered)
        prev = ciphered
    return ''.join(ct_blocks)

def decrypt_cbc(cipher_hex: str, key_str: str, iv_hex: str) -> str:
    # CBC decrypt and unpad
    key_bytes = utf8_to_bytes(key_str)[:8].ljust(8, b'\x00')
    keys = generate_round_keys(key_bytes.hex().upper())
    prev = iv_hex.upper()
    pt_hex_parts = []
    for i in range(0, len(cipher_hex), 16):
        blk = cipher_hex[i:i+16]
        dec = decrypt_block(blk, keys)
        xored = bits_to_hex(xor_bits(hex_to_bits(dec), hex_to_bits(prev)))
        pt_hex_parts.append(xored)
        prev = blk
    data = hex_to_bytes(''.join(pt_hex_parts))
    pad_len = data[-1]
    return bytes_to_utf8(data[:-pad_len])

def triple_des_encrypt_ecb(plaintext: str, key_str: str) -> str:
    # EDE-3DES in ECB mode
    master = key_str.encode('utf-8')[:24].ljust(24, b'\x00')
    K1, K2, K3 = master[:8], master[8:16], master[16:24]
    R1 = generate_round_keys(K1.hex().upper())
    R2 = generate_round_keys(K2.hex().upper())
    R3 = generate_round_keys(K3.hex().upper())
    padded = pad_bytes(plaintext.encode('utf-8'))
    pt_hex = padded.hex().upper()
    out = []
    for i in range(0, len(pt_hex), 16):
        blk = pt_hex[i:i+16]
        c1 = encrypt_block(blk, R1)
        c2 = decrypt_block(c1, R2)
        c3 = encrypt_block(c2, R3)
        out.append(c3)
    return ''.join(out)

def triple_des_decrypt_ecb(cipher_hex: str, key_str: str) -> str:
    # DED-3DES in ECB mode
    master = key_str.encode('utf-8')[:24].ljust(24, b'\x00')
    K1, K2, K3 = master[:8], master[8:16], master[16:24]
    R1 = generate_round_keys(K1.hex().upper())
    R2 = generate_round_keys(K2.hex().upper())
    R3 = generate_round_keys(K3.hex().upper())
    pt_hex_chunks = []
    for i in range(0, len(cipher_hex), 16):
        blk = cipher_hex[i:i+16]
        y1 = decrypt_block(blk, R3)
        y2 = encrypt_block(y1, R2)
        p  = decrypt_block(y2, R1)
        pt_hex_chunks.append(p)
    data = hex_to_bytes(''.join(pt_hex_chunks))
    pad_len = data[-1]
    return bytes_to_utf8(data[:-pad_len])

def triple_des_encrypt_cbc(plaintext: str, key_str: str, iv: str) -> str:
    # EDE-3DES in CBC mode
    master = key_str.encode('utf-8')[:24].ljust(24, b'\x00')
    K1, K2, K3 = master[:8], master[8:16], master[16:24]
    R1 = generate_round_keys(K1.hex().upper())
    R2 = generate_round_keys(K2.hex().upper())
    R3 = generate_round_keys(K3.hex().upper())
    padded = pad_bytes(plaintext.encode('utf-8'))
    pt_hex = padded.hex().upper()
    iv_hex = utf8_to_hex(iv)
    prev = iv_hex.upper()
    ct_chunks = []
    for i in range(0, len(pt_hex), 16):
        blk = pt_hex[i:i+16]
        x = bits_to_hex(xor_bits(hex_to_bits(blk), hex_to_bits(prev)))
        y1 = encrypt_block(x, R1)
        y2 = decrypt_block(y1, R2)
        c  = encrypt_block(y2, R3)
        ct_chunks.append(c)
        prev = c
    return ''.join(ct_chunks)

def triple_des_decrypt_cbc(cipher_hex: str, key_str: str, iv: str) -> str:
    # DED-3DES in CBC mode
    master = key_str.encode('utf-8')[:24].ljust(24, b'\x00')
    K1, K2, K3 = master[:8], master[8:16], master[16:24]
    R1 = generate_round_keys(K1.hex().upper())
    R2 = generate_round_keys(K2.hex().upper())
    R3 = generate_round_keys(K3.hex().upper())
    iv_hex = utf8_to_hex(iv)
    prev = iv_hex.upper()
    pt_hex_parts = []
    for i in range(0, len(cipher_hex), 16):
        blk = cipher_hex[i:i+16]
        y1 = decrypt_block(blk, R3)
        y2 = encrypt_block(y1, R2)
        x  = decrypt_block(y2, R1)
        p  = bits_to_hex(xor_bits(hex_to_bits(x), hex_to_bits(prev)))
        pt_hex_parts.append(p)
        prev = blk
    data = hex_to_bytes(''.join(pt_hex_parts))
    pad_len = data[-1]
    return bytes_to_utf8(data[:-pad_len])
