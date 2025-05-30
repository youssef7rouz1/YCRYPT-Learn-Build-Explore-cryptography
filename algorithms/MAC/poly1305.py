from typing import List
from utils.useful_functions import *

def clamp_r(r_bytes: bytes) -> int:
    """
    Clamp the 16-byte r portion of the Poly1305 key:
      - clear bits 4..7 of bytes 3,7,11,15
      - clear bits 0..1 of bytes 4,8,12
    Returns a 128-bit integer.
    """
    if len(r_bytes) != 16:
        raise ValueError("r_bytes must be 16 bytes")
    ba = bytearray(r_bytes)
    # clear high nibble of bytes 3,7,11,15
    for i in (3, 7, 11, 15):
        ba[i] &= 0x0F
    # clear low 2 bits of bytes 4,8,12
    for i in (4, 8, 12):
        ba[i] &= 0xFC
    return int.from_bytes(ba, 'little')

def prepare_message(aad: bytes, ciphertext: bytes) -> List[int]:
    
    def pad16(data: bytes) -> bytes:
        if len(data) % 16 == 0:
            return data
        pad_len = 16 - (len(data) % 16)
        return data + b'\x00' * pad_len

    aad_p = pad16(aad)
    ct_p  = pad16(ciphertext)
    # lengths as 64-bit little-endian
    aad_len = len(aad).to_bytes(8, 'little')
    ct_len  = len(ciphertext).to_bytes(8, 'little')

    full = aad_p + ct_p + aad_len + ct_len
    blocks = []
    for i in range(0, len(full), 16):
        chunk = full[i:i+16]
        # interpret little-endian, then add the '1' bit at position 8*len(chunk)
        m = int.from_bytes(chunk, 'little') + (1 << (8 * len(chunk)))
        blocks.append(m)
    return blocks

def poly1305_mac(r: int, s: int, blocks: List[int]) -> int:
    """
    Compute Poly1305 MAC over the sequence of 128-bit message blocks.
    Returns a 128-bit integer tag.
    """
    p = (1 << 130) - 5
    acc = 0
    for m in blocks:
        acc = (acc + m) % p
        acc = (acc * r) % p
    tag = (acc + s) & ((1 << 128) - 1)
    return tag

def poly1305(key: str, aad: str, msg: str) -> bytes:
    
    key=utf8_to_bytes(key)
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    r = clamp_r(key[:16])
    s = int.from_bytes(key[16:], 'little')
    blocks = prepare_message(utf8_to_bytes(aad), utf8_to_bytes(msg))
    tag_int = poly1305_mac(r, s, blocks)
    return tag_int.to_bytes(16, 'little')


