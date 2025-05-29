import os
from datetime import datetime
from flask import Flask, render_template, request
from dotenv import load_dotenv


from algorithms.symmetric.AES import (
    encrypt_ecb, decrypt_ecb,
    encrypt_cbc, decrypt_cbc,
    encrypt_ctr, decrypt_ctr
)

load_dotenv()
app = Flask(__name__)

# inject current_year into every template
@app.context_processor
def inject_current_year():
    return {"current_year": datetime.utcnow().year}

# ─── Category → algos ─────────────────────────────────────────────────────────
ALGOS = {
  "symmetric": [
    { "key": "AES_128",  "label": "AES 128" },
    { "key": "AES_192",  "label": "AES 192" },
    { "key": "AES_256",  "label": "AES 256" },
    { "key": "caesar",   "label": "Caesar Cipher" },
    { "key": "ChaCha20", "label": "ChaCha20" },
    { "key": "columnar","label": "Columnar Transposition" },
    { "key": "DES",      "label": "DES" },
    { "key": "3DES",     "label": "3DES" },
    { "key": "playfair","label": "Playfair Cipher" },
    { "key": "rc4",      "label": "RC4" },
    { "key": "vigenere","label": "Vigenère Cipher" }
  ],
  "AEAD": [
    { "key": "AES_GCM",       "label": "AES-GCM" },
    { "key": "ChaCha20_Poly","label": "ChaCha20-Poly1305" },
    { "key": "XChaChaPoly",  "label": "XChaCha20-Poly1305" }
  ],
  "hashing": [
    { "key": "MD4",    "label": "MD4" },
    { "key": "MD5",    "label": "MD5" },
    { "key": "SHA256", "label": "SHA-256" },
    { "key": "SHA512", "label": "SHA-512" },
    { "key": "SHA1", "label": "SHA_1" },
    { "key": "SHA3_224", "label": "SHA-3 224" },
    { "key": "SHA3_256", "label": "SHA-3 256" },
    { "key": "SHA3_384", "label": "SHA-3 384" },
    { "key": "SHA3_512", "label": "SHA-3 512" }
    
  ],
  "HMAC": [
    { "key": "HMAC", "label": "HMAC" }
  ],
  "MAC": [
    { "key": "poly1305", "label": "Poly1305" },
    
  ]
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
     "required":False, "placeholder":"16 ASCII chars or leave blank"},
    {"name":"key",        "type":"text",     "label":"Secret Key (16-byte ASCII)",
     "required":True,  "placeholder":"Exactly 16 chars"}
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
     "required":False, "placeholder":"16 ASCII chars or leave blank"},
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
     "required":False, "placeholder":"16 ASCII chars or leave blank"},
    {"name":"key",        "type":"text",     "label":"Secret Key (32-byte ASCII)",
     "required":True,  "placeholder":"Exactly 32 chars"}
  ],
  
    "caesar": [
        # 1) Action toggle
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        # 2a) Plaintext for encryption
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext ",
            "required":  True,
            "show_when": "Encrypt"
        },
        # 2b) Ciphertext for decryption
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext",
            "required":  True,
            "show_when": "Decrypt"
        },
        # 3) Shift parameter
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
        # 1) Encrypt vs. Decrypt toggle
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        # 2a) Only when Encrypt
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext",
            "required":  True,
            "show_when": "Encrypt"
        },
        # 2b) Only when Decrypt
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext",
            "required":  True,
            "show_when": "Decrypt"
        },
        # 3) The key/keyword
        {
            "name":     "key",
            "type":     "text",
            "label":    "Keyword",
            "required": True,
            "placeholder": "Your columnar key"
        },
        # 4) Optional pad character
        {
            "name":        "pad",
            "type":        "text",
            "label":       "Fill-pad character",
            "required":    False,
            "placeholder": "_ (underscore by default)"
        }
    ],

    "ChaCha20": [
        # 1) Encrypt vs. Decrypt toggle
        {
            "name":     "action",
            "type":     "select",
            "label":    "Action",
            "options":  ["Encrypt", "Decrypt"],
            "required": True
        },
        # 2a) Plaintext for encryption
        {
            "name":      "plaintext",
            "type":      "textarea",
            "label":     "Plaintext (UTF-8)",
            "required":  True,
            "show_when": "Encrypt"
        },
        # 2b) Ciphertext for decryption
        {
            "name":      "ciphertext",
            "type":      "textarea",
            "label":     "Ciphertext (hex)",
            "required":  True,
            "show_when": "Decrypt"
        },
        # 3) Shared parameters
        {
            "name":     "key",
            "type":     "text",
            "label":    "Key (ASCII, up to 32 chars)",
            "required": True,
            "placeholder": "32-byte key (will be zero-padded/truncated)"
        },
        {
            "name":     "nonce",
            "type":     "text",
            "label":    "Nonce (ASCII, up to 12 chars)",
            "required": True,
            "placeholder": "12-byte nonce (will be zero-padded/truncated)"
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
            "label":       "IV (16-hex digits, only for CBC)",
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
    "SHA1": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA256": [
        {
            "name":     "message",
            "type":     "textarea",
            "label":    "Message",
            "required": True,
            "rows":     4,
            "placeholder": "Type your message here…"
        }
    ],
    "SHA512": [
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
        # choose encrypt or decrypt
        {"name":"action","type":"select","label":"Action",
         "options":["Encrypt","Decrypt"],"required":True},

        # only for encrypt
        {"name":"plaintext","type":"textarea","label":"Plaintext",
         "required":True,"rows":4,"placeholder":"Type plaintext…",
         "show_when":"Encrypt"},

        # only for decrypt
        {"name":"ciphertext","type":"textarea","label":"Ciphertext (hex)",
         "required":True,"rows":4,"placeholder":"Paste hex…",
         "show_when":"Decrypt"},
        {"name":"tag","type":"text","label":"Tag (hex)",
         "required":True,"placeholder":"Paste authentication tag…",
         "show_when":"Decrypt"},

        # common params
        {"name":"key","type":"text","label":"Key (ASCII)",
         "required":True,"placeholder":"Enter your key…"},
        {"name":"nonce","type":"text","label":"Nonce (ASCII)",
         "required":True,"placeholder":"Enter your nonce…"},
        {"name":"aad","type":"textarea","label":"AAD (optional)",
         "required":False,"rows":2,"placeholder":"Additional data…"},
    ],

    # ChaCha20-Poly1305
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

    # XChaCha20-Poly1305
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
      "placeholder": "Enter exactly 32 ASCII characters"
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
            "MD4", "MD5", "SHA-1", "SHA-256", "SHA-512",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        ],
        "required": True
    }
]






def run_algorithm(category, algo, **kwargs):
    """
    Dispatch to the right implementation based on algo, mode & action.
    """
    # AES-128, 192, 256 all use the same AES_* functions:
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

    # … add other algorithms here …

  

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
