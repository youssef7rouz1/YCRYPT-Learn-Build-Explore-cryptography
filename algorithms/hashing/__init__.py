# algorithms/hashing/__init__.py

from .MD4     import md4
from .MD5     import md5
from .SHA1    import sha1
from .SHA3 import sha3_384 , sha3_224 , sha3_256 ,sha3_512
from .sha_256 import  sha256
from .sha_512 import sha512

HASH_ALGORITHMS = {
    "MD4":      md4,
    "MD5":      md5,
    "SHA_1":     sha1,
    "SHA_256":   sha256,
    "SHA_512":   sha512,
    "SHA3_224": sha3_224,
    "SHA3_256": sha3_256,
    "SHA3_384": sha3_384,
    "SHA3_512": sha3_512,
}
