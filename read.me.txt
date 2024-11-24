# AES Image and Text Encryption/Decryption

This project implements AES encryption and decryption for text and BMP images using three modes:
- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CTR (Counter)

## Features
- Encrypt and decrypt plaintext and BMP images.
- Supports three AES modes: ECB, CBC, and CTR.
- Uses SHA-256 for secure key hashing.
- Random initialization vectors (IVs) for CBC and CTR.

## Prerequisites
- Python 3.x
- Libraries: `pycryptodome`, `Pillow`

Install the required libraries using:
```bash
pip install pycryptodome Pillow
