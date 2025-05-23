import os
import string
from typing import List


def permute(block: int, table: List[int], n_bits: int) -> int:
    """Apply an n-bit permutation ‘table’ to the integer ‘block’ and return new int."""

def left_rotate28(bits28: int, n: int) -> int:
    """Rotate a 28-bit value left by n positions (mod 28)."""

def generate_subkeys(master_key64: int) -> List[int]:
    """
    - Apply PC-1 → two 28-bit halves.
    - For rounds 1…16: rotate halves, apply PC-2 → yield 48-bit subkey.
    - Return list of 16 subkeys.
    """

def initial_permutation(block64: int) -> int:
    """Apply the IP table to a 64-bit block."""

def final_permutation(block64: int) -> int:
    """Apply the inverse-IP table to a 64-bit block."""

def feistel(R32: int, subkey48: int) -> int:
    """
    - E-expand R32 → R48
    - XOR with subkey48
    - Split into 8 chunks → run through S-boxes → reassemble 32 bits
    - Apply P-permutation → return 32 bit result
    """

def des_encrypt_block(block64: int, master_key64: int) -> int:
    """
    - IP → split to L0,R0
    - for i in 1…16: Li, Ri = Ri₋₁, Li₋₁ ⊕ feistel(Ri₋₁, Ki)
    - preoutput = R16‖L16
    - return FP(preoutput)
    """

def des_decrypt_block(block64: int, master_key64: int) -> int:
    """Same as encrypt, but apply the subkeys in reverse order."""
