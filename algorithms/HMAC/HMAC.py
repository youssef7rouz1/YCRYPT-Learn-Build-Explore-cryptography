
from algorithms.hashing import HASH_ALGORITHMS
from typing import Dict           
from utils.useful_functions import (
    
    hex_to_bytes,
    bytes_to_hex,
    xor_bytes,
    utf8_to_bytes
)


# --------------------------------------------------------------------------- #
# HMAC block sizes (bytes)
_BLOCK_SIZES: Dict[str, int] = {
    # MD / SHA-1 / SHA-2 families
    "MD4": 64,
    "MD5": 64,
    "SHA_1": 64,
    "SHA_256": 64,
    "SHA_512": 128,
    # SHA-3 
    "SHA3_224": 144,
    "SHA3_256": 136,
    "SHA3_384": 104,
    "SHA3_512": 72,
}


# --------------------------------------------------------------------------- #
def _get_block_size(name: str) -> int:
    try:
        return _BLOCK_SIZES[name]
    except KeyError:
        raise ValueError(f"Unknown hash algorithm {name!r}")

# --------------------------------------------------------------------------- #
def _hash_bytes(data: bytes, name: str) -> bytes:
   
    hfn = HASH_ALGORITHMS.get(name)
    if hfn is None:
        raise ValueError(f"Unknown hash algorithm {name!r}")

    hex_digest = hfn(data.decode("latin-1"))
    return hex_to_bytes(hex_digest)          


# --------------------------------------------------------------------------- #
def _prepare_key(key: str, name: str) -> bytes:
 
    block = _get_block_size(name)
    k = utf8_to_bytes(key)

    if len(k) > block:
        k = _hash_bytes(k, name)             

    return k.ljust(block, b"\x00")           


# --------------------------------------------------------------------------- #
def hmac(key: str, msg: str, hash_name: str) -> str:
   
    block = _get_block_size(hash_name)
    k0 = _prepare_key(key, hash_name)
    m  = utf8_to_bytes(msg)

    o_key_pad = xor_bytes(k0, b"\x5c" * block)
    i_key_pad = xor_bytes(k0, b"\x36" * block)

    inner = _hash_bytes(i_key_pad + m,        hash_name)
    tag   = _hash_bytes(o_key_pad + inner,    hash_name)

    return bytes_to_hex(tag)

# --------------------------------------------------------------------------- #

