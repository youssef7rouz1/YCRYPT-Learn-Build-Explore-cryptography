import base64

def bytes_to_bits(data: bytes) -> str:
    """Convert bytes into a string of bits (e.g. '01010101')."""
    return "".join(f"{byte:08b}" for byte in data)

def bits_to_bytes(bits: str) -> bytes:
    """Convert a string of bits back into bytes."""
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))

def hex_to_bytes(hex_str: str) -> bytes:
    """Turn a hex string into raw bytes."""
    return bytes.fromhex(hex_str)

def bytes_to_hex(data: bytes) -> str:
    """Turn bytes into an uppercase hex string."""
    return data.hex().upper()

def hex_to_bits(hex_str: str) -> str:
    """Convert a hex string into its bit representation."""
    return bytes_to_bits(bytes.fromhex(hex_str))

def bits_to_hex(bits: str) -> str:
    """Convert a bit string into an uppercase hex string."""
    return bytes_to_hex(bits_to_bytes(bits))

def utf8_to_bytes(text: str) -> bytes:
    """Encode text into bytes (1 char → 1 byte)."""
    return text.encode("latin-1")

def bytes_to_utf8(data: bytes) -> str:
    """Decode bytes back into text."""
    return data.decode("latin-1", errors="replace")

def utf8_to_hex(text: str) -> str:
    """Encode text to hex via Latin-1."""
    return bytes_to_hex(utf8_to_bytes(text))

def hex_to_utf8(hex_str: str) -> str:
    """Decode a hex string into text."""
    return bytes_to_utf8(bytes.fromhex(hex_str))

def utf8_to_bits(text: str) -> str:
    """Convert text directly into a bit string."""
    return bytes_to_bits(utf8_to_bytes(text))

def bits_to_utf8(bits: str) -> str:
    """Convert a bit string back into text."""
    return bytes_to_utf8(bits_to_bytes(bits))

def bytes_to_base64(data: bytes) -> str:
    """Encode bytes into Base64."""
    return base64.b64encode(data).decode("ascii")

def base64_to_bytes(b64_str: str) -> bytes:
    """Decode a Base64 string into bytes."""
    return base64.b64decode(b64_str)

def hex_to_base64(hex_str: str) -> str:
    """Convert hex string into Base64."""
    return bytes_to_base64(bytes.fromhex(hex_str))

def base64_to_hex(b64_str: str) -> str:
    """Convert Base64 string into uppercase hex."""
    return bytes_to_hex(base64.b64decode(b64_str))

def bits_to_base64(bits: str) -> str:
    """Convert bit string into Base64."""
    return bytes_to_base64(bits_to_bytes(bits))

def base64_to_bits(b64_str: str) -> str:
    """Convert Base64 string into a bit string."""
    return bytes_to_bits(base64.b64decode(b64_str))

def base64_to_utf8(b64_str: str) -> str:
    """Decode Base64 string into text."""
    return bytes_to_utf8(base64.b64decode(b64_str))

def utf8_to_base64(text: str) -> str:
    """Encode text directly into Base64."""
    return bytes_to_base64(utf8_to_bytes(text))

def int_to_bytes(n: int, length: int, byteorder: str = "big") -> bytes:
    """Convert an integer into a fixed-length byte sequence."""
    return n.to_bytes(length, byteorder)

def bytes_to_int(b: bytes, byteorder: str = "big") -> int:
    """Convert bytes back into an integer."""
    return int.from_bytes(b, byteorder)

def pad_bytes(data: bytes, block_size: int = 8) -> bytes:
    """Add PKCS#7 padding to a byte string."""
    pad_len = block_size - (len(data) % block_size) or block_size
    return data + bytes([pad_len]) * pad_len

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def chunk_bytes(data: bytes, size: int) -> list[bytes]:
    """Split bytes into chunks of the given size."""
    return [data[i : i + size] for i in range(0, len(data), size)]

def rotate_left(x: int, shift: int, width: int) -> int:
    """Rotate an integer left by a fixed width."""
    mask = (1 << width) - 1
    return ((x << shift) & mask) | (x >> (width - shift))

def rotate_right(x: int, shift: int, width: int) -> int:
    """Rotate an integer right by a fixed width."""
    mask = (1 << width) - 1
    return (x >> shift) | ((x << (width - shift)) & mask)

def left_shift(bits: str, n: int) -> str:
    """Shift a bit-string left by n bits."""
    width = len(bits)
    x = int(bits, 2)
    r = rotate_left(x, n, width)
    return f"{r:0{width}b}"

def right_shift(bits: str, n: int) -> str:
    """Shift a bit-string right by n bits."""
    width = len(bits)
    x = int(bits, 2)
    r = rotate_right(x, n, width)
    return f"{r:0{width}b}"

def xor_bits(a: str, b: str) -> str:
    """XOR two bit-strings of equal length."""
    return "".join("0" if x == y else "1" for x, y in zip(a, b))

def modexp(base: int, exp: int, mod: int) -> int:
    """Efficient modular exponentiation."""
    result = 1
    base %= mod
    while exp:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result

def egcd(a: int, b: int):
    """Extended GCD algorithm."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modinv(a: int, m: int) -> int:
    """Modular inverse via extended GCD."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def gf256_mul(a: int, b: int, poly: int = 0x11B) -> int:
    """Multiply two GF(2^8) elements."""
    res = 0
    while b:
        if b & 1:
            res ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= poly
    return res & 0xFF

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Apply PKCS#7 padding to data."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding, raising on error."""
    pad_len = data[-1]
    if not 1 <= pad_len <= len(data):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]
