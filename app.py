import os
from datetime import datetime
from flask import Flask, render_template, request
from dotenv import load_dotenv

# Symmetric ciphers
from algorithms.symmetric.AES import (
    encrypt_ecb, decrypt_ecb,
    encrypt_cbc, decrypt_cbc,
    encrypt_ctr, decrypt_ctr,
)
from algorithms.symmetric.caesar import encrypt as caesar_encrypt, decrypt as caesar_decrypt
from algorithms.symmetric.ChaCha20 import (
    chacha20_encrypt, chacha20_decrypt,
    xchacha20_encrypt, xchacha20_decrypt,
)
from algorithms.symmetric.columnar_transpostion import encrypt as columnar_encrypt, decrypt as columnar_decrypt
from algorithms.symmetric.DES import (
    encrypt_ecb as des_encrypt_ecb, decrypt_ecb as des_decrypt_ecb,
    encrypt_cbc as des_encrypt_cbc, decrypt_cbc as des_decrypt_cbc,
    triple_des_encrypt_ecb, triple_des_decrypt_ecb,
    triple_des_encrypt_cbc, triple_des_decrypt_cbc,
)
from algorithms.symmetric.playfair import encrypt as playfair_encrypt, decrypt as playfair_decrypt
from algorithms.symmetric.rc4 import encrypt as rc4_encrypt, decrypt as rc4_decrypt
from algorithms.symmetric.vigenere import encrypt as vigenere_encrypt, decrypt as vigenere_decrypt

# Hash functions
from algorithms.hashing.MD4 import md4
from algorithms.hashing.MD5 import md5
from algorithms.hashing.sha_256 import sha256
from algorithms.hashing.sha_512 import sha512
from algorithms.hashing.SHA1 import sha1
from algorithms.hashing.SHA3 import sha3_224, sha3_256, sha3_384, sha3_512

# AEAD
from algorithms.AEAD.AES_GCM import aes_gcm_encrypt, aes_gcm_decrypt
from algorithms.AEAD.ChaCha20_Poly1305 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from algorithms.AEAD.XChaChaPoly1305 import xchacha20_poly1305_encrypt, xchacha20_poly1305_decrypt

# HMAC
from algorithms.HMAC.HMAC import hmac

load_dotenv()
app = Flask(__name__)

@app.context_processor
def inject_current_year():
    return {"current_year": datetime.utcnow().year}

# Available algorithms for the UI
ALGOS = {
    "symmetric": [
        {"key": "AES_128",  "label": "AES 128"},
        {"key": "AES_192",  "label": "AES 192"},
        {"key": "AES_256",  "label": "AES 256"},
        {"key": "caesar",   "label": "Caesar Cipher"},
        {"key": "ChaCha20", "label": "ChaCha20"},
        {"key": "XChaCha20","label": "XChaCha20"},
        {"key": "columnar","label": "Columnar Transposition"},
        {"key": "DES",      "label": "DES"},
        {"key": "3DES",     "label": "3DES"},
        {"key": "playfair","label": "Playfair"},
        {"key": "rc4",      "label": "RC4"},
        {"key": "vigenere","label": "Vigenère"},
    ],
    "AEAD": [
        {"key": "AES_GCM",       "label": "AES-GCM"},
        {"key": "ChaCha20_Poly", "label": "ChaCha20-Poly1305"},
        {"key": "XChaChaPoly",   "label": "XChaCha20-Poly1305"},
    ],
    "hashing": [
        {"key": "MD4",     "label": "MD4"},
        {"key": "MD5",     "label": "MD5"},
        {"key": "SHA_256", "label": "SHA-256"},
        {"key": "SHA_512", "label": "SHA-512"},
        {"key": "SHA_1",   "label": "SHA-1"},
        {"key": "SHA3_224","label": "SHA-3 224"},
        {"key": "SHA3_256","label": "SHA-3 256"},
        {"key": "SHA3_384","label": "SHA-3 384"},
        {"key": "SHA3_512","label": "SHA-3 512"},
    ],
    "HMAC": [
        {"key": "HMAC", "label": "HMAC"},
    ],
    "MAC": [
        {"key": "poly1305", "label": "Poly1305"},
    ],
}

# ─── Algorithm → form‐fields schema ────────────────────────────────────────────
ALGO_PARAMS = {
  "AES_128": [
    {"name":"action",     "type":"select",   "label":"Action",
     "options":["Encrypt","Decrypt"], "required":True},
    {"name":"plaintext",  "type":"textarea","label":"Plaintext",
     "required":True,  "show_when":"Encrypt"},
    {"name":"ciphertext","type":"textarea","label":"Ciphertext (hex)",
     "required":True,  "show_when":"Decrypt"},
    {"name":"mode",       "type":"select",   "label":"Mode",
     "options":["ECB","CBC","CTR"], "required":True},
    {"name":"padding",    "type":"select",   "label":"Padding",
     "options":["PKCS7"],   "required":True},
    {"name":"iv",         "type":"text",     "label":"IV (optional  , in ASCII)",
     "required":False, "placeholder":"16 ASCII chars or leave blank","show_when_mode": ["CBC","CTR"]},
    {"name":"key",        "type":"text",     "label":"Secret Key (16-byte ASCII)",
     "required":True,  "placeholder":"Exactly 16 chars" , "minlength" : 16 , "maxlength" : 16 , "pattern" : ".{16}", "title"  : "Key must be exactly 16 characters long"}
  ],
  "AES_192": [
    {"name":"action",     "type":"select",   "label":"Action",
     "options":["Encrypt","Decrypt"], "required":True},
    {"name":"plaintext",  "type":"textarea","label":"Plaintext",
     "required":True,  "show_when":"Encrypt"},
    {"name":"ciphertext","type":"textarea","label":"Ciphertext (hex)",
     "required":True,  "show_when":"Decrypt"},
    {"name":"mode",       "type":"select",   "label":"Mode",
     "options":["ECB","CBC","CTR"], "required":True},
    {"name":"padding",    "type":"select",   "label":"Padding",
     "options":["PKCS7"],   "required":True},
    {"name":"iv",         "type":"text",     "label":"IV (optional  , in ASCII)",
     "required":False, "placeholder":"16 ASCII chars or leave blank" , "show_when_mode": ["CBC","CTR"]},
    {"name":"key",        "type":"text",     "label":"Secret Key (24-byte ASCII)",
     "required":True,  "placeholder":"Exactly 24 chars"}
  ],
  "AES_256": [
    {"name":"action",     "type":"select",   "label":"Action",
     "options":["Encrypt","Decrypt"], "required":True},
    {"name":"plaintext",  "type":"textarea","label":"Plaintext",
     "required":True,  "show_when":"Encrypt"},
    {"name":"ciphertext","type":"textarea","label":"Ciphertext (hex)",
     "required":True,  "show_when":"Decrypt"},
    {"name":"mode",       "type":"select",   "label":"Mode",
     "options":["ECB","CBC","CTR"], "required":True},
    {"name":"padding",    "type":"select",   "label":"Padding",
     "options":["PKCS7"],   "required":True},
    {"name":"iv",         "type":"text",     "label":"IV (optional  , in ASCII)",
     "required":False, "placeholder":"16 ASCII chars or leave blank" , "show_when_mode": ["CBC","CTR"]},
    {"name":"key",        "type":"text",     "label":"Secret Key (32-byte ASCII)",
     "required":True,  "placeholder":"Exactly 32 chars"}
  ],
  
    "caesar": [
       
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext ",
            "required":  True,
            "show_when": "Encrypt"
        },
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext",
            "required":  True,
            "show_when": "Decrypt"
        },
        {
            "name":     "shift",
            "type":     "number",
            "label":    "Shift (>0)",
            "required": True,
            "min":      0,
            
            "value":    3
        }
    ],

    "columnar": [
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext",
            "required":  True,
            "show_when": "Encrypt"
        },
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext",
            "required":  True,
            "show_when": "Decrypt"
        },
        {
            "name":     "key",
            "type":     "text",
            "label":    "Keyword",
            "required": True,
            "placeholder": "Your columnar key"
        },
        {
            "name":        "pad",
            "type":        "text",
            "label":       "Fill-pad character",
            "required":    False,
            "placeholder": "_ (underscore by default)"
        }
    ],

    "ChaCha20": [
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext (UTF-8)",
            "required":  True,
            "show_when": "Encrypt"
        },
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext (hex)",
            "required":  True,
            "show_when": "Decrypt"
        },
        {
            "name":     "key",
            "type":     "text",
            "label":    "Key (ASCII, up to 32 chars)",
            "required": True,
            "placeholder": "32-byte key (will be zero-padded/truncated)",
            "minlength" : 32 , "maxlength" : 32 , "pattern" : ".{32}", "title"  : "Key must be exactly 32 characters long"

        },
        {
            "name":     "nonce",
            "type":     "text",
            "label":    "Nonce (ASCII, up to 12 chars)",
            "required": True,
            "placeholder": "12-byte nonce " , 
            "minlength" : 12 , "maxlength" : 12 , "pattern" : ".{12}", "title"  : "Nonce must be exactly 12 characters long"
        },
        {
            "name":      "initial_counter",
            "type":      "number",
            "label":     "Initial Counter",
            "placeholder": " equals 1 by default" , 
            "required":  False,
            "value":     1,
            "min":       0
        }
    ],
    "XChaCha20": [
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext (UTF-8)",
            "required":  True,
            "show_when": "Encrypt"
        },
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext (hex)",
            "required":  True,
            "show_when": "Decrypt"
        },
        {
            "name":     "key",
            "type":     "text",
            "label":    "Key (ASCII, up to 32 chars)",
            "required": True,
            "placeholder": "32-byte key ",
            "minlength" : 32 , "maxlength" : 32 , "pattern" : ".{32}", "title"  : "Key must be exactly 32 characters long"
        },
        {
            "name":     "nonce",
            "type":     "text",
            "label":    "Nonce (ASCII, up to 12 chars)",
            "required": True,
            "placeholder": "12-byte nonce (will be zero-padded/truncated)", 
            "minlength" : 16 , "maxlength" : 16 , "pattern" : ".{16}", "title"  : "Nonce must be exactly 16 characters long"
        },
        {
            "name":      "initial_counter",
            "type":      "number",
            "label":     "Initial Counter",
            "required":  False,
            "value":     1,
            "min":       0
        }
    ],
     "DES": [
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext",
            "required":  True,
            "show_when": "Encrypt"
        },
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext (hex)",
            "required":  True,
            "show_when": "Decrypt"
        },
        {
            "name":     "mode",
            "type":     "select",
            "label":    "Mode",
            "options":  ["ECB", "CBC"],
            "required": True
        },
        {
            "name":        "key",
            "type":        "text",
            "label":       "Secret Key (8-byte ASCII)",
            "required":    True,
            "placeholder": "e.g. 8 characters"
        },
        {
            "name":        "iv",
            "type":        "text",
            "label":       "IV (16-hex digits, only for CBC)",
            "required":    False,
            "placeholder": "e.g. 0123456789ABCDEF"
        }
    ],

    "3DES": [
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext",
            "required":  True,
            "show_when": "Encrypt"
        },
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext (hex)",
            "required":  True,
            "show_when": "Decrypt"
        },
        {
            "name":     "mode",
            "type":     "select",
            "label":    "Mode",
            "options":  ["ECB", "CBC"],
            "required": True
        },
        {
            "name":        "key",
            "type":        "text",
            "label":       "Secret Key (24-byte ASCII)",
            "required":    True,
            "placeholder": "e.g. 24 characters"
        },
        {
            "name":        "iv",
            "type":        "text",
            "label":       "IV (utf-8)",
            "required":    False,
            "placeholder": "e.g. 0123456789ABCDEF"
        }
    ],
    
    "playfair": [
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext",
            "required":  True,
            "show_when": "Encrypt"
        },
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext",
            "required":  True,
            "show_when": "Decrypt"
        },
        {
            "name":        "key",
            "type":        "text",
            "label":       "Keyword",
            "required":    True,
            "placeholder": "Enter letters A–Z (J→I)"
        }
    ],
    "rc4": [
    {
        "name":    "action",
        "type":    "select",
        "label":   "Action",
        "options": ["Encrypt", "Decrypt"],
        "required": True
    },
    {
        "name":      "plaintext",
        "type":      "textarea",
        "label":     "Plaintext",
        "required":  True,
        "show_when": "Encrypt"
    },
    {
        "name":      "ciphertext",
        "type":      "textarea",
        "label":     "Ciphertext (hex)",
        "required":  True,
        "show_when": "Decrypt"
    },
    {
        "name":        "key",
        "type":        "text",
        "label":       "Key",
        "required":    True,
        "placeholder": "Enter stream-cipher key"
    }
],
"vigenere": [
    {
        "name":    "action",
        "type":    "select",
        "label":   "Action",
        "options": ["Encrypt", "Decrypt"],
        "required": True
    },
    {
        "name":      "plaintext",
        "type":      "textarea",
        "label":     "Plaintext",
        "required":  True,
        "show_when": "Encrypt"
    },
    {
        "name":      "ciphertext",
        "type":      "textarea",
        "label":     "Ciphertext",
        "required":  True,
        "show_when": "Decrypt"
    },
    {
        "name":        "key",
        "type":        "text",
        "label":       "Keyword",
        "required":    True,
        "placeholder": "Enter keyword (letters only)"
    },
    {
        "name":        "alphabet",
        "type":        "text",
        "label":       "Alphabet",
        "required":    True,
        "placeholder": "e.g. ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    }
],
"MD4": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "MD5": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA_1": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA_256": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA_512": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA3_224": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA3_256": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA3_384": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA3_512": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
     "AES_GCM": [
        {"name":"action","type":"select","label":"Action",
         "options":["Encrypt","Decrypt"],"required":True},

        {"name":"plaintext","type":"textarea","label":"Plaintext",
         "required":True,"rows":4,"placeholder":"Type plaintext…",
         "show_when":"Encrypt"},

        {"name":"ciphertext","type":"textarea","label":"Ciphertext (hex)",
         "required":True,"rows":4,"placeholder":"Paste hex…",
         "show_when":"Decrypt"},
        {"name":"tag","type":"text","label":"Tag (hex)",
         "required":True,"placeholder":"Paste authentication tag…",
         "show_when":"Decrypt"},

        {"name":"key","type":"text","label":"Key (ASCII)",
         "required":True,"placeholder":"Enter your key…"},
        {"name":"nonce","type":"text","label":"Nonce (ASCII)",
         "required":True,"placeholder":"Enter your nonce…"},
        {"name":"aad","type":"textarea","label":"AAD (optional)",
         "required":False,"rows":2,"placeholder":"Additional data…"},
    ],

    "ChaCha20_Poly": [
    { "name": "action",     "type": "select",   "label": "Action",
      "options": ["Encrypt", "Decrypt"],      "required": True },

    { "name": "plaintext",  "type": "textarea","label": "Plaintext",
      "required": True,    "rows": 4,
      "show_when": "Encrypt",
      "placeholder": "Type the text you want to encrypt…" },

    { "name": "ciphertext", "type": "textarea","label": "Ciphertext (hex)",
      "required": True,    "rows": 4,
      "show_when": "Decrypt",
      "placeholder": "Paste the hex-encoded ciphertext…" },

    { "name": "tag",        "type": "text",    "label": "Tag (hex)",
      "required": True,
      "show_when": "Decrypt",
      "placeholder": "Paste the authentication tag (hex)…" },

    { "name": "key",        "type": "text",    "label": "Key (ASCII)",
      "required": True,
      "placeholder": "Enter your 32-byte key…" },

    { "name": "nonce",      "type": "text",    "label": "Nonce (ASCII)",
      "required": True,
      "placeholder": "Enter a 12-byte nonce…" },

    { "name": "aad",        "type": "textarea","label": "AAD (optional)",
      "required": False,   "rows": 2,
      "placeholder": "Additional authenticated data (optional)…" },
],

    "XChaChaPoly": [
        {"name":"action","type":"select","label":"Action",
         "options":["Encrypt","Decrypt"],"required":True},

        {"name":"plaintext","type":"textarea","label":"Plaintext",
         "required":True,"rows":4,"show_when":"Encrypt"},
        {"name":"ciphertext","type":"textarea","label":"Ciphertext (hex)",
         "required":True,"rows":4,"show_when":"Decrypt"},
        {"name":"tag","type":"text","label":"Tag (hex)",
         "required":True,"show_when":"Decrypt"},

        {"name":"key","type":"text","label":"Key (ASCII, 32 bytes)",
         "required":True,"placeholder":"32-byte key…"},
        {"name":"nonce","type":"text","label":"Nonce (ASCII, 24 bytes)",
         "required":True,"placeholder":"24-byte nonce…"},
        {"name":"aad","type":"textarea","label":"AAD (optional)",
         "required":False,"rows":2},
    ],
    "poly1305": [
    {
      "name":        "key",
      "type":        "text",
      "label":       "One-time Key (ASCII, 32 bytes)",
      "required":    True,
      "placeholder": "Enter exactly 32 ASCII characters" , 
      "minlength" : 32 , "maxlength" : 32 , "pattern" : ".{32}", "title"  : "Key must be exactly 32 characters long"
    },
    {
      "name":        "aad",
      "type":        "textarea",
      "label":       "AAD (optional)",
      "required":    False,
      "rows":        2,
      "placeholder": "Additional authenticated data…"
    },
    {
      "name":        "msg",
      "type":        "textarea",
      "label":       "Message",
      "required":    True,
      "rows":        4,
      "placeholder": "Enter the message to authenticate"
    }
],
"Ghash" : [ {
        "name":        "H",
        "type":        "text",
        "label":       "Hash Subkey H (hex)",
        "required":    True,
        "placeholder": "32 hex characters (16 bytes)"
    },
    {
        "name":        "aad",
        "type":        "textarea",
        "label":       "AAD (optional)",
        "required":    False,
        "rows":        2,
        "placeholder": "Additional Authenticated Data…"
    },
    {
        "name":        "ciphertext",
        "type":        "textarea",
        "label":       "Ciphertext (hex)",
        "required":    True,
        "rows":        4,
        "placeholder": "Ciphertext to hash…"
    }]
  
}

ALGO_PARAMS["HMAC"] = [
    {
        "name":     "key",
        "type":     "text",
        "label":    "Secret Key",
        "required": True,
        "placeholder": "Enter your HMAC key…"
    },
    {
        "name":     "message",
        "type":     "textarea",
        "label":    "Message",
        "required": True,
        "rows":     4,
        "placeholder": "Type your message here…"
    },
    {
        "name":     "hash_name",
        "type":     "select",
        "label":    "Hash Algorithm",
        "options":  [
            "MD4", "MD5", "SHA_1", "SHA_256", "SHA_512",
            "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
        ],
        "required": True
    }
]



def run_algorithm(category, algo, **kwargs):
    """
    Dispatch to the right implementation based on algo, mode & action.
    """
    
    if algo in ("AES_128","AES_192","AES_256"):
        action = kwargs.pop("action")            # "Encrypt" or "Decrypt"
        mode   = kwargs.pop("mode")              # "ECB", "CBC" or "CTR"
        key    = kwargs.pop("key")               # ASCII key
        iv     = kwargs.pop("iv","")             # ASCII IV or ""  
        # plaintext vs ciphertext field names:
        if action == "Encrypt":
            pt = kwargs.pop("plaintext")
            if mode == "ECB":
                return encrypt_ecb(pt, key)
            elif mode == "CBC":
                return encrypt_cbc(pt, key, iv)
            else:  # CTR
                return encrypt_ctr(pt, key, iv)
        else:  # Decrypt
            ct = kwargs.pop("ciphertext")
            if mode == "ECB":
                return decrypt_ecb(ct, key)
            elif mode == "CBC":
                return decrypt_cbc(ct, key, iv)
            else:
                return decrypt_ctr(ct, key, iv)
    elif algo == "caesar":
        action = kwargs.pop("action")   # "Encrypt" or "Decrypt"
        # pop shift and convert to integer
        shift  = int(kwargs.pop("shift"))

        if action == "Encrypt":
            pt = kwargs.pop("plaintext")
            return caesar_encrypt(pt, shift)
        else:  # Decrypt
            ct = kwargs.pop("ciphertext")
            return caesar_decrypt(ct, shift)
    elif algo == "ChaCha20":
        # pop the shared params
        action           = kwargs.pop("action")            # "Encrypt" or "Decrypt"
        key_str          = kwargs.pop("key")               # ASCII key
        nonce_str        = kwargs.pop("nonce")             # ASCII nonce
        # initial_counter may be missing → default to 1
        initial_counter  = int(kwargs.pop("initial_counter", 1))

        if action == "Encrypt":
            plaintext = kwargs.pop("plaintext")
            return chacha20_encrypt(plaintext, key_str, nonce_str, initial_counter)
        else:
            ciphertext = kwargs.pop("ciphertext")
            return chacha20_decrypt(ciphertext, key_str, nonce_str, initial_counter)

    elif algo == "XChaCha20":
        # same pattern for the 24-byte variant
        action           = kwargs.pop("action")
        key_str          = kwargs.pop("key")
        nonce_str        = kwargs.pop("nonce")
        initial_counter  = int(kwargs.pop("initial_counter", 1))

        if action == "Encrypt":
            plaintext = kwargs.pop("plaintext")
            return xchacha20_encrypt(plaintext, key_str, nonce_str, initial_counter)
        else:
            ciphertext = kwargs.pop("ciphertext")
            return xchacha20_decrypt(ciphertext, key_str, nonce_str, initial_counter)
    elif algo == "columnar":
        action = kwargs.pop("action")             # "Encrypt" or "Decrypt"
        key    = kwargs.pop("key")                # your columnar keyword
        # pad is optional—default to '_' if not supplied
        pad    = kwargs.pop("pad", "_") or "_"

        if action == "Encrypt":
            plaintext = kwargs.pop("plaintext")
            return columnar_encrypt(plaintext, key, pad)
        else:
            ciphertext = kwargs.pop("ciphertext")
            return columnar_decrypt(ciphertext, key, pad)
    elif algo == "DES":
        action = kwargs.pop("action")      # "Encrypt" or "Decrypt"
        mode   = kwargs.pop("mode")        # "ECB" or "CBC"
        key    = kwargs.pop("key")         # ASCII 8-byte key
        iv     = kwargs.pop("iv", "")      # hex-IV for CBC, or blank

        if action == "Encrypt":
            pt = kwargs.pop("plaintext")
            if mode == "ECB":
                return des_encrypt_ecb(pt, key)
            else:  # CBC
                return des_encrypt_cbc(pt, key, iv)
        else:  # Decrypt
            ct = kwargs.pop("ciphertext")
            if mode == "ECB":
                return des_decrypt_ecb(ct, key)
            else:
                return des_decrypt_cbc(ct, key, iv)

    elif algo == "3DES":
        action = kwargs.pop("action")
        mode   = kwargs.pop("mode")
        key    = kwargs.pop("key")         # ASCII 24-byte key
        iv     = kwargs.pop("iv", "")      # hex-IV for CBC, or blank

        if action == "Encrypt":
            pt = kwargs.pop("plaintext")
            if mode == "ECB":
                return triple_des_decrypt_ecb(pt, key)
            else:  # CBC
                return triple_des_encrypt_cbc(pt, key, iv)
        else:
            ct = kwargs.pop("ciphertext")
            if mode == "ECB":
                return triple_des_decrypt_ecb(ct, key)
            else:
                return triple_des_decrypt_cbc(ct, key, iv)
    elif algo == "playfair":
        action = kwargs.pop("action")    # "Encrypt" or "Decrypt"
        key    = kwargs.pop("key")       # your keyword
        if action == "Encrypt":
            pt = kwargs.pop("plaintext")
            return playfair_encrypt(pt, key)
        else:
            ct = kwargs.pop("ciphertext")
            return playfair_decrypt(ct, key)
    elif algo == "rc4":
        action = kwargs.pop("action")      # “Encrypt” or “Decrypt”
        key    = kwargs.pop("key")         # ASCII key
        if action == "Encrypt":
            pt = kwargs.pop("plaintext")
            return rc4_encrypt(pt, key)
        else:
            ct = kwargs.pop("ciphertext")
            return rc4_decrypt(ct, key)
    elif algo == "vigenere":
        action   = kwargs.pop("action")       # "Encrypt" or "Decrypt"
        key      = kwargs.pop("key")          # keyword (letters only)
        alphabet = kwargs.pop("alphabet")     # custom alphabet
        if action == "Encrypt":
            pt = kwargs.pop("plaintext")
            return vigenere_encrypt(pt, key, alphabet)
        else:
            ct = kwargs.pop("ciphertext")
            return vigenere_decrypt(ct, key, alphabet)
    elif category == "hashing":
        msg = kwargs.pop("message")
        fn  = HASH_FUNCS.get(algo)
        if fn is None:
            raise ValueError(f"Unknown hash algorithm {algo!r}")
        return fn(msg)
    elif algo == "AES_GCM":
        action    = kwargs.pop("action")
        key_str   = kwargs.pop("key")
        nonce_str = kwargs.pop("nonce")
        aad       = kwargs.pop("aad", "")

        if action == "Encrypt":
            plaintext = kwargs.pop("plaintext")
            ct_hex, tag_hex = aes_gcm_encrypt(plaintext, key_str, nonce_str, aad)
            return f"{ct_hex} ‖ tag: {tag_hex}"
        else:
            cipher_hex = kwargs.pop("ciphertext")
            tag_hex    = kwargs.pop("tag")
            try:
                pt = aes_gcm_decrypt(cipher_hex, tag_hex, key_str, nonce_str, aad)
            except ValueError as e:
                return f"ERROR: {e}"
            return pt
    elif algo == "ChaCha20_Poly":
        action           = kwargs.pop("action")
        key_str          = kwargs.pop("key")
        nonce_str        = kwargs.pop("nonce")
        aad              = kwargs.pop("aad", "")
        initial_counter  = int(kwargs.pop("initial_counter", 1))

        if action == "Encrypt":
            plaintext = kwargs.pop("plaintext")
            ct_hex, tag_hex = chacha20_poly1305_encrypt(
                plaintext, key_str, nonce_str, aad, initial_counter
            )
            return f"{ct_hex} ‖ tag: {tag_hex}"
        else:
            cipher_hex = kwargs.pop("ciphertext")
            tag_hex    = kwargs.pop("tag")
            try:
                pt = chacha20_poly1305_decrypt(
                    cipher_hex, tag_hex, key_str, nonce_str, aad, initial_counter
                )
            except ValueError as e:
                return f"ERROR: {e}"
            return pt
    elif algo == "XChaChaPoly":
        action          = kwargs.pop("action")
        key_str         = kwargs.pop("key")
        nonce_str       = kwargs.pop("nonce")
        aad             = kwargs.pop("aad", "")
        initial_counter = int(kwargs.pop("initial_counter", 1))

        if action == "Encrypt":
            plaintext = kwargs.pop("plaintext")
            ct_hex, tag_hex = xchacha20_poly1305_encrypt(
                plaintext,
                key_str,
                nonce_str,
                aad,
                initial_counter
            )
            return f"{ct_hex}  (tag: {tag_hex})"
        else:
            cipher_hex = kwargs.pop("ciphertext")
            tag_hex    = kwargs.pop("tag")
            try:
                pt = xchacha20_poly1305_decrypt(
                    cipher_hex,
                    tag_hex,
                    key_str,
                    nonce_str,
                    aad,
                    initial_counter
                )
            except ValueError as e:
                return f"ERROR: {e}"
            return pt
    elif algo == "HMAC":
        key       = kwargs.pop("key")
        message   = kwargs.pop("message")
        hash_name = kwargs.pop("hash_name")
        try:
            return hmac(key, message, hash_name)
        except ValueError as e:
            return f"ERROR: {e}"

@app.route("/", methods=["GET","POST"])
def index():
    result = None
    if request.method == "POST":
        data      = request.form.to_dict()
        category  = data.pop("category", "")
        algorithm = data.pop("algorithm", "")
        result    = run_algorithm(category, algorithm, **data)

    return render_template(
        "index.html",
        categories=list(ALGOS.keys()),
        algos=ALGOS,
        algo_params=ALGO_PARAMS,
        result=result
    )

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/source_code")
def source_code():
    return render_template("sourcecode.html")

@app.route("/tools")
def tools():
    return render_template("tools.html")

if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
