import os
import struct  
import string           
from typing import List, Tuple
def rotl32(x: int, n: int) -> int:
    """
    Rotate the 32-bit word x left by n bits (0 ≤ n < 32), modulo 2³².
    """

def quarter_round(a: int, b: int, c: int, d: int) -> List[int]:
    """
    Apply the ChaCha quarter-round to four 32-bit words (a,b,c,d) and return
    their updated values.
    """

def chacha20_init_state(key: bytes, counter: int, nonce: bytes) -> List[int]:
    """
    Build the 16-word (32-bit) internal state array from:
      - 4 constant words,
      - 8 words of key,
      - 1 word of block counter,
      - 3 words of nonce.
    Returns a list of 16 ints.
    """


def chacha20_block(state: List[int]) -> bytes:
    """
    Given a 16-word state, make a working copy, run 20 rounds (alternating
    column and diagonal QR mixes), add the original state back in, then
    serialize to 64 output bytes (little-endian).
    """

def chacha20_encrypt(plaintext: str,
                     key: str,
                     nonce: bytes,
                     initial_counter: int = 0) -> bytes:
    """
    Slice plaintext into 64-byte chunks, for each:
      1. initialize state with key, counter, nonce,
      2. generate keystream block via chacha20_block(),
      3. XOR keystream against plaintext chunk,
      4. increment counter.
    Returns the concatenated ciphertext bytes.
    """

def le_bytes_to_u32(bs: bytes) -> int:
    """Convert 4-byte little-endian sequence to a 32-bit int."""
def u32_to_le_bytes(x: int) -> bytes:
    """Convert a 32-bit int to 4-byte little-endian sequence."""
