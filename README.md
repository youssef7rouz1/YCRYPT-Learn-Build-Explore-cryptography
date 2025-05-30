# YCrypt

[![Python Version](https://img.shields.io/badge/Python-3.13-blue?logo=python)](https://www.python.org/)  
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green?logo=flask)](https://flask.palletsprojects.com/)  
[![Pytest](https://img.shields.io/badge/pytest-8.3.5-orange?logo=pytest)](https://docs.pytest.org/)

YCrypt is an educational Flask-based web application demonstrating a variety of cryptographic algorithms—symmetric, hashing, MAC, HMAC, and AEAD—implemented in pure Python so you can learn exactly how each algorithm works under the hood.

---

## Table of Contents
1. [Project Overview](#project-overview)  
2. [Directory Structure](#directory-structure)  
3. [Features](#features)  
4. [Installation](#installation)  
5. [Usage](#usage)  
6. [Running Tests](#running-tests)  
7. [Contributing](#contributing)  
8. [License](#license)  
9. [Contact](#contact)  

---

## Project Overview
YCrypt serves as both a reference and a learning tool for students and practitioners of cybersecurity, offering:
- **Clear Python implementations** of over 30 algorithms across major cryptographic categories.  
- **Flask-powered web interface** for browsing, experimenting, and understanding each algorithm.  
- **Automated test suite** ensuring correctness with `pytest`.  

---

## Directory Structure
```text
.
├── app.py                   # Main Flask application
├── algorithms/              # Pure-Python algorithm implementations
│   ├── symmetric/           # AES, DES, RC4, Vigenère, etc.
│   ├── hashing/             # SHA-256, SHA-512, MD5, SHA3, etc.
│   ├── HMAC/                
│   ├── MAC/                 # Poly1305, GHASH, etc.
│   └── AEAD/                # AES-GCM, ChaCha20-Poly1305, etc.
├── templates/               # Jinja2 HTML templates
├── static/                  # CSS & JavaScript assets
├── tests/                   # `pytest` test cases for each algorithm
├── utils/                   # Shared helper functions & constants
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

## Features

✅ **Deep-dive implementations**  
Each algorithm is written from scratch in Python, with extensive inline comments—perfect for understanding exactly how cryptography works at the bit level.

✅ **Hands-on learning**  
The Flask-powered UI lets you input plaintext, keys, nonces, etc., and see live encryption, decryption, or digest outputs. Great for experimentation and demos.

✅ **Comprehensive coverage**  
Includes symmetric ciphers (AES, DES, RC4, Vigenère…), hashing functions (SHA-2, SHA-3, MD-series), HMAC, MAC (Poly1305, GHASH), and AEAD modes (AES-GCM, ChaCha20-Poly1305).

✅ **Test-driven correctness**  
Over 100 pytest tests ensure each algorithm matches standard vectors. Ideal for validating your own implementations or learning test-driven development.

✅ **Modular & extensible**  
Well-organized package structure means you can drop in new algorithms, swap implementations, or integrate with other projects in minutes.

✅ **Educational resource**  
Whether you’re a student, educator, or self-learner, YCrypt offers a transparent, runnable codebase to demystify modern cryptography.





## Installation

Clone the repository

```bash
git clone https://github.com/youssef7rouz1/YCrypt.git
cd YCrypt
```

Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
```

Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```


## Usage

(Optional) Copy and edit environment file

```bash
cp .env.example .env
# Edit .env to configure SECRET_KEY, etc.
```

Run the Flask app

```bash
flask run
```

Open your browser at http://localhost:5000

## Running Tests

Run the full test suite with pytest:

```bash
pytest
```

Or a specific test:

```bash
pytest tests/test_sha256.py
```
## Contact

[![Author](https://img.shields.io/badge/Author-Youssef7rouz-blue)](https://github.com/youssef7rouz1)  
[![Email](https://img.shields.io/badge/Email-youssefbenbenabdeljelil@gmail.com-blue)](mailto:youssefbenbenabdeljelil@gmail.com)  
[![GitHub](https://img.shields.io/badge/GitHub-youssef7rouz1-blue?logo=github)](https://github.com/youssef7rouz1)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-youssef7rouz1-blue?logo=linkedin)](https://www.linkedin.com/in/youssef-ben-abdeljelil-586b252b4/)



Feel free to reach out for questions, collaboration, or feedback! 🚀





