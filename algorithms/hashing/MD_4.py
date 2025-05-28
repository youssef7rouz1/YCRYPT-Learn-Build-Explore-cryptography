from utils.useful_functions import utf8_to_bytes , bytes_to_utf8 , hex_to_utf8 , utf8_to_hex  , chunk_bytes ,bytes_to_hex ,  bytes_to_int , rotate_left
def md4_pad(message: bytes) -> bytes : # Pads the message to a multiple of 512 bits (append 0x80, zero-bytes, then 64-bit length LE).

    padded=message + b'\x80'  
    zeros_to_pad_length=(56-(len(padded)%64)) %64
    padded+=b'\x00'*zeros_to_pad_length
    bit_len = len(message) * 8
    padded += bit_len.to_bytes(8, byteorder='little')
    return padded

def md4_parse_blocks(padded: bytes) -> list[list[int]] :  # Splits the padded message into 512-bit blocks and for each block returns a list of sixteen 32-bit little-endian words.
    if len(padded) % 64 != 0:
        raise ValueError("Padded message length must be a multiple of 64 bytes")
    blocks: list[list[int]] = []
    for block in chunk_bytes(padded , 64):
        words=[]
        for word_bytes in chunk_bytes(block, 4):
            words.append(bytes_to_int(word_bytes ,byteorder= 'little'))
        blocks.append(words)
    return blocks

         
def F(x: int, y: int, z: int) -> int : 
    return  (x & y) | (~x & z)

def G(x: int, y: int, z: int) -> int: 
    return (x & y) | (x & z) | (y & z) 

def H(x: int, y: int, z: int) -> int : 
    return x ^ y ^ z

#The three Boolean functions used in rounds 1, 2, 3 respectively.


def rotl32(x: int, s: int) -> int : 
 # Left-rotate a 32-bit word
    return rotate_left(x , s , 32)

def md4_round1(A, B, C, D, X):
    a, b, c, d = A, B, C, D
    s = [3, 7, 11, 19]
    for i in range(16):
        # 1) mix
        a = (a + F(b, c, d) + X[i]) & 0xFFFFFFFF
        # 2) rotate
        a = rotl32(a, s[i % 4])
        # 3) cycle registers
        a, b, c, d = d, a, b, c
    # Return the updated quartet
    return a, b, c, d

def md4_round2(A, B, C, D, X):
    a, b, c, d = A, B, C, D
    K2=0x5A827999
    message_order=[ 0,  4,  8, 12,
  1,  5,  9, 13,
  2,  6, 10, 14,
  3,  7, 11, 15 ]
    s = [3, 5, 9, 13]
    for i in range(16):
        k=message_order[i]
        # 1) mix
        a = (a + G(b, c, d) + X[k]+K2) & 0xFFFFFFFF
        # 2) rotate
        a = rotl32(a, s[i % 4])
        # 3) cycle registers
        a, b, c, d = d, a, b, c
    # Return the updated quartet
    return a, b, c, d

def md4_round3(A, B, C, D, X):
    a, b, c, d = A, B, C, D
    K3=0x6ED9EBA1
    s = [3,9,11,15]
    message_order=[ 0,  8,  4, 12,
  2, 10,  6, 14,
  1,  9,  5, 13,
  3, 11,  7, 15 ]
    for i in range(16):
        k=message_order[i]
        # 1) mix
        a = (a + H(b, c, d) +X[k] + K3) & 0xFFFFFFFF
        # 2) rotate
        a = rotl32(a, s[i % 4])
        # 3) cycle registers
        a, b, c, d = d, a, b, c
    # Return the updated quartet
    return a, b, c, d

def md4_compress_block(state: tuple[int,int,int,int], X: list[int]) -> tuple[int,int,int,int] : 
    # Calls the three rounds in sequence, then adds back the saved state.
    A, B, C, D = state
    AA, BB, CC, DD = A, B, C, D
    A, B, C, D = md4_round1(A, B, C, D, X)
    A, B, C, D = md4_round2(A, B, C, D, X)
    A, B, C, D = md4_round3(A, B, C, D, X)
    A = (A + AA) & 0xFFFFFFFF
    B = (B + BB) & 0xFFFFFFFF
    C = (C + CC) & 0xFFFFFFFF
    D = (D + DD) & 0xFFFFFFFF
    return A, B, C, D




def md4_init_state() -> tuple[int,int,int,int]:
    """
    Return the MD4 initial 128-bit state as four 32-bit words (A, B, C, D).
    """
    return (
        0x67452301,  # A
        0xEFCDAB89,  # B
        0x98BADCFE,  # C
        0x10325476,  # D
    )
def md4_finalize(state: tuple[int,int,int,int]) -> bytes:
    """
    Take the final 128-bit state (A, B, C, D) and
    return the 16-byte MD4 digest, little-endian.
    """
    A, B, C, D = state
    # to_bytes(4, 'little') emits each 32-bit word as 4 bytes, least-significant byte first
    return (
        A.to_bytes(4, byteorder='little') +
        B.to_bytes(4, byteorder='little') +
        C.to_bytes(4, byteorder='little') +
        D.to_bytes(4, byteorder='little')
    )
def md4(message: str) -> hex : 
    message_bytes=utf8_to_bytes(message)
    padded=md4_pad(message_bytes)
    blocks=md4_parse_blocks(padded)
    A , B  , C , D =md4_init_state()

    for block in blocks : 
        A , B  , C , D = md4_compress_block((A , B  , C , D),block)
    return bytes_to_hex(md4_finalize((A , B  , C , D)))



if __name__ == "__main__":
    h = md4("hello")
    print(h)  # should print: aa010fbc1d14c795d86ef98c95479d17