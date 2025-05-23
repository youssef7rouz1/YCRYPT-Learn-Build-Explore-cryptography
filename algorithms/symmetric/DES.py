import binascii
from utils.conversion_padding_functions import (
    hex_to_bits,
    bits_to_hex,
    pad_bytes,
    utf8_to_bytes,
    bytes_to_utf8,
    hex_to_bytes,
)
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

# XOR two bit-strings of equal length

def xor_bits(a, b):
    return ''.join('0' if x == y else '1' for x, y in zip(a, b))

# Rotate-left shift on bit-string

def left_shift(bits, n):
    return bits[n:] + bits[:n]

# Permute bits according to 1-based table

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
def main():
    print(encrypt_ecb('fpkefojgojg', 'secret!'))
    print(decrypt_ecb(encrypt_ecb('fpkefojgojg', 'secret!'), 'secret!'))

if __name__ == '__main__':
    main()
