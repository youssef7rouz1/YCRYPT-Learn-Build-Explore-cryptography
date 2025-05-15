import os
from datetime import datetime
from flask import Flask, render_template, request
from dotenv import load_dotenv

# ─── Configuration ────────────────────────────────────────────────────────────

load_dotenv()  # loads FLASK_DEBUG, PORT, etc.

app = Flask(__name__)

def current_year():
    return datetime.now().year

# ─── Crypto Pages Configuration ────────────────────────────────────────────────

PAGE_CATEGORIES = {
    "encrypt": ["symmetric", "asymmetric"],
    "decrypt": ["symmetric", "asymmetric"],
    
}

# ─── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        mode="home",
        categories=[],
        result=None
    )

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    mode       = "encrypt"
    categories = PAGE_CATEGORIES[mode]
    result     = None

    if request.method == "POST":
        category  = request.form.get("category", "")
        algorithm = request.form.get("algorithm", "")
        message   = request.form.get("message", "")
        params    = {
            k: v for k, v in request.form.items()
            if k not in ("category", "algorithm", "message")
        }
        # TODO: replace with your real encryption call
        result = f"[Encrypt] {category}.{algorithm}('{message}') → {params}"

    return render_template(
        "index.html",
        mode=mode,
        categories=categories,
        result=result
    )

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    mode       = "decrypt"
    categories = PAGE_CATEGORIES[mode]
    result     = None

    if request.method == "POST":
        category   = request.form.get("category", "")
        algorithm  = request.form.get("algorithm", "")
        ciphertext = request.form.get("message", "")
        params     = {
            k: v for k, v in request.form.items()
            if k not in ("category", "algorithm", "message")
        }
        # TODO: replace with your real decryption call
        result = f"[Decrypt] {category}.{algorithm}('{ciphertext}') → {params}"

    return render_template(
        "index.html",
        mode=mode,
        categories=categories,
        result=result
    )

@app.route("/sign", methods=["GET", "POST"])
def sign():
    mode       = "sign"
    
    result     = None

    if request.method == "POST":
        algorithm = request.form.get("algorithm", "")
        message   = request.form.get("message", "")
        params    = {
            k: v for k, v in request.form.items()
            if k not in ("algorithm", "message")
        }
        # TODO: replace with your real sign/verify call
        result = f"[Sign] {algorithm}('{message}') → {params}"

    return render_template(
        "index.html",
        mode=mode,
        
        result=result
    )

# Note: we explicitly set endpoint="hash" so url_for('hash') works
@app.route("/hash", methods=["GET", "POST"], endpoint="hash")
def hash_page():
    mode       = "hash"
    
    result     = None

    if request.method == "POST":
        algorithm = request.form.get("algorithm", "")
        message   = request.form.get("message", "")
        # TODO: replace with your real hash call
        result = f"[Hash] {algorithm}('{message}')"

    return render_template(
        "index.html",
        mode=mode,
        
        result=result
        
    )

@app.route("/HMAC", methods=["GET", "POST"], endpoint="HMAC")
def hash_page():
    mode       = "HMAC"
    
    result     = None

    if request.method == "POST":
        algorithm = request.form.get("algorithm", "")
        message   = request.form.get("message", "")
        # TODO: replace with your real hash call
        result = f"[HMAC] {algorithm}('{message}')"

    return render_template(
        "index.html",
        mode=mode,
        
        result=result
        
    )

@app.route("/contact", methods=["GET"])
def contact():
    return render_template(
        "contact.html"
        
    )

@app.route("/explanations", methods=["GET"])
def explanations():
    return render_template(
        "Explanations.html"
    )

@app.route("/sourcecode", methods=["GET"])
def sourcecode():
    return render_template(
        "SourceCode.html"
    )

@app.route("/tools", methods=["GET"])
def tools():
    return render_template(
        "tools.html"
    )

# ─── Run the App ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
