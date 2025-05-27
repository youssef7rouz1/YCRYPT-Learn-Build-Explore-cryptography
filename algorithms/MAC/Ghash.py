from utils.useful_functions import chunk_bytes, int_to_bytes, bytes_to_int

# GF(2^128) multiplication with the reduction polynomial
# x^128 + x^7 + x^2 + x + 1 (0xE1 << 120)
R = 0xE1000000000000000000000000000000

def gf128_mul(x: int, y: int) -> int:
    """
    Multiply two 128-bit integers in GF(2^128) with the standard AES GCM polynomial.
    """
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        # shift x right by 1; if LSB was 1, apply reduction
        if x & 1:
            x = (x >> 1) ^ R
        else:
            x >>= 1
    return z & ((1 << 128) - 1)


def ghash(H: bytes, A: bytes, C: bytes) -> bytes:
    """
    GHASH(H, A, C) as defined in GCM:
      - H: 16-byte hash subkey
      - A: additional authenticated data
      - C: ciphertext
    Returns 16-byte authentication tag.
    """
    H_int = bytes_to_int(H, 'big')
    X = 0
    # process AAD
    for block in chunk_bytes(A, 16):
        if len(block) < 16:
            block = block.ljust(16, b'\x00')
        X = gf128_mul(X ^ bytes_to_int(block, 'big'), H_int)
    # process ciphertext
    for block in chunk_bytes(C, 16):
        if len(block) < 16:
            block = block.ljust(16, b'\x00')
        X = gf128_mul(X ^ bytes_to_int(block, 'big'), H_int)
    # lengths block: 64-bit bit-lengths of A and C
    len_block = int_to_bytes(len(A) * 8, 8, 'big') + int_to_bytes(len(C) * 8, 8, 'big')
    X = gf128_mul(X ^ bytes_to_int(len_block, 'big'), H_int)
    return int_to_bytes(X, 16, 'big')
