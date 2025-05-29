import base64

# ────────────────────────── Byte / Bit conversions ──────────────────────────

def bytes_to_bits(data: bytes) -> str:
    """Return a bit‑string (e.g. "010101") representing *data*."""
    return "".join(f"{byte:08b}" for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    """Convert a bit‑string back to bytes. *len(bits)* must be a multiple of 8."""
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))

# ─────────────────────────────── Hex helpers ────────────────────────────────

def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def hex_to_bits(hex_str: str) -> str:
    return bytes_to_bits(bytes.fromhex(hex_str))


def bits_to_hex(bits: str) -> str:
    return bytes_to_hex(bits_to_bytes(bits))



def utf8_to_bytes(text: str) -> bytes:  
    """Encode *text* using Latin‑1 (1 char ⇆ 1 byte)."""
    return text.encode("latin-1")


def bytes_to_utf8(data: bytes) -> str:  
    """Decode *data* with Latin‑1.  Exact inverse of ``utf8_to_bytes``."""
    return data.decode("latin-1", errors="replace")


def utf8_to_hex(text: str) -> str:
    return bytes_to_hex(utf8_to_bytes(text))


def hex_to_utf8(hex_str: str) -> str:
    return bytes_to_utf8(bytes.fromhex(hex_str))


def utf8_to_bits(text: str) -> str:
    return bytes_to_bits(utf8_to_bytes(text))


def bits_to_utf8(bits: str) -> str:
    return bytes_to_utf8(bits_to_bytes(bits))

# ───────────────────────────── Base‑64 helpers ──────────────────────────────

def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64_to_bytes(b64_str: str) -> bytes:
    return base64.b64decode(b64_str)


def hex_to_base64(hex_str: str) -> str:
    return bytes_to_base64(bytes.fromhex(hex_str))


def base64_to_hex(b64_str: str) -> str:
    return bytes_to_hex(base64.b64decode(b64_str))


def bits_to_base64(bits: str) -> str:
    return bytes_to_base64(bits_to_bytes(bits))


def base64_to_bits(b64_str: str) -> str:
    return bytes_to_bits(base64.b64decode(b64_str))


def base64_to_utf8(b64_str: str) -> str:
    return bytes_to_utf8(base64.b64decode(b64_str))


def utf8_to_base64(text: str) -> str:
    return bytes_to_base64(utf8_to_bytes(text))

# ───────────────────────────── Integer helpers ──────────────────────────────

def int_to_bytes(n: int, length: int, byteorder: str = "big") -> bytes:
    return n.to_bytes(length, byteorder)


def bytes_to_int(b: bytes, byteorder: str = "big") -> int:
    return int.from_bytes(b, byteorder)

# ─────────────────────────── Padding / misc helpers ─────────────────────────

def pad_bytes(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size) or block_size
    return data + bytes([pad_len]) * pad_len


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def chunk_bytes(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def rotate_left(x: int, shift: int, width: int) -> int:
    mask = (1 << width) - 1
    return ((x << shift) & mask) | (x >> (width - shift))


def rotate_right(x: int, shift: int, width: int) -> int:
    mask = (1 << width) - 1
    return (x >> shift) | ((x << (width - shift)) & mask)


# bit‑string helpers ---------------------------------------------------------

def left_shift(bits: str, n: int) -> str:
    width = len(bits)
    x = int(bits, 2)
    r = rotate_left(x, n, width)
    return f"{r:0{width}b}"


def right_shift(bits: str, n: int) -> str:
    width = len(bits)
    x = int(bits, 2)
    r = rotate_right(x, n, width)
    return f"{r:0{width}b}"


def xor_bits(a: str, b: str) -> str:
    return "".join("0" if x == y else "1" for x, y in zip(a, b))

# maths helpers --------------------------------------------------------------

def modexp(base: int, exp: int, mod: int) -> int:
    result = 1
    base %= mod
    while exp:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

# finite‑field helper --------------------------------------------------------

def gf256_mul(a: int, b: int, poly: int = 0x11B) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= poly
    return res & 0xFF

# PKCS#7 helpers -------------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if not 1 <= pad_len <= len(data):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]
