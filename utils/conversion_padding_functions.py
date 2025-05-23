import base64

# Byte and Bit conversions
# -------------------------

def bytes_to_bits(data: bytes) -> str:
    """Convert bytes to a bit string."""
    return ''.join(f"{byte:08b}" for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    """Convert a bit string into bytes. Length must be multiple of 8."""
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# Hex conversions
# ----------------

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to uppercase hex string."""
    return data.hex().upper()


def hex_to_bits(hex_str: str) -> str:
    """Convert hex string to bit string."""
    return bytes_to_bits(bytes.fromhex(hex_str))


def bits_to_hex(bits: str) -> str:
    """Convert bit string to uppercase hex string."""
    return bytes_to_hex(bits_to_bytes(bits))

# UTF-8 (text) conversions
# -------------------------

def utf8_to_bytes(text: str) -> bytes:
    """Encode a UTF-8 string to bytes."""
    return text.encode('utf-8')


def bytes_to_utf8(data: bytes) -> str:
    """Decode bytes (UTF-8) to string."""
    return data.decode('utf-8', errors='replace')


def utf8_to_hex(text: str) -> str:
    """Encode UTF-8 text to hex string."""
    return bytes_to_hex(text.encode('utf-8'))


def hex_to_utf8(hex_str: str) -> str:
    """Decode hex string into a UTF-8 string."""
    return bytes_to_utf8(bytes.fromhex(hex_str))


def utf8_to_bits(text: str) -> str:
    """Encode UTF-8 text to bit string."""
    return bytes_to_bits(text.encode('utf-8'))


def bits_to_utf8(bits: str) -> str:
    """Decode bit string into a UTF-8 string."""
    return bytes_to_utf8(bits_to_bytes(bits))

# Base64 conversions
# -------------------

def bytes_to_base64(data: bytes) -> str:
    """Encode bytes to a base64 string."""
    return base64.b64encode(data).decode('ascii')


def base64_to_bytes(b64_str: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(b64_str)


def hex_to_base64(hex_str: str) -> str:
    """Convert hex string to base64 string."""
    return bytes_to_base64(bytes.fromhex(hex_str))


def base64_to_hex(b64_str: str) -> str:
    """Convert base64 string to uppercase hex string."""
    return bytes_to_hex(base64.b64decode(b64_str))


def bits_to_base64(bits: str) -> str:
    """Convert bit string to base64 string."""
    return bytes_to_base64(bits_to_bytes(bits))


def base64_to_bits(b64_str: str) -> str:
    """Convert base64 string to bit string."""
    return bytes_to_bits(base64.b64decode(b64_str))

# Padding helper (PKCS#5)
# ------------------------------------------------------------------

def pad_bytes(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size) or block_size
    return data + bytes([pad_len]) * pad_len