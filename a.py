#!/usr/bin/env python3
"""
Generate secret.enc from an HTML file.

The decryption key is derived (PBKDF2-HMAC-SHA256) from the concatenation
of a username and password. The output file packs everything the browser
needs to reproduce the key and decrypt:

    [ "magic" | version | iterations(4) | salt(16) | iv(12) | ciphertext+tag ]

Usage:
    python encrypt.py body.html secret.enc
    # then enter username and password when prompted
"""

import os
import sys
import struct
import getpass
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ENC1"          # 4 bytes, lets the JS sanity-check the file
ITERATIONS = 310_000     # PBKDF2 rounds (OWASP-ish for SHA256)
SALT_LEN = 16
IV_LEN = 12              # 96-bit nonce, standard for GCM


def derive_key(username: str, password: str, salt: bytes, iterations: int) -> bytes:
    # The "key" the user types is username + password, concatenated.
    secret = (username + password).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", secret, salt, iterations, dklen=32)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input.html> <output.enc>", file=sys.stderr)
        return 1

    in_path, out_path = sys.argv[1], sys.argv[2]

    with open(in_path, "rb") as f:
        plaintext = f.read()

    username = input("Username: ")
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        return 1

    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = derive_key(username, password, salt, ITERATIONS)

    # AES-GCM; the 16-byte auth tag is appended to the ciphertext automatically.
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)

    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(">I", ITERATIONS))
        f.write(salt)
        f.write(iv)
        f.write(ciphertext)

    print(f"Wrote {out_path} ({len(plaintext)} bytes plaintext "
          f"-> {os.path.getsize(out_path)} bytes encrypted).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())