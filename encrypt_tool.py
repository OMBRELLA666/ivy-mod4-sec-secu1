#!/usr/bin/env python3
"""
crypto_toolkit.py

Features:
1. SHA-256 hash generator (strings and files)
2. Caesar cipher (encrypt/decrypt)
3. Digital signature demo using OpenSSL (generate keys, sign, verify)
"""

import hashlib
import subprocess
from pathlib import Path


# ============================================================
# 1. SHA-256 HASHING
# ============================================================

def hash_string(text: str) -> str:
    """Return the SHA-256 hex digest of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_file(file_path: str) -> str:
    """Return the SHA-256 hex digest of a file (read in chunks)."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256 = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def sha256_menu():
    while True:
        print("\n=== SHA-256 Hash Generator ===")
        print("1) Hash a string")
        print("2) Hash a file")
        print("3) Back to main menu")
        choice = input("Choose an option (1–3): ").strip()

        if choice == "1":
            text = input("Enter the text to hash: ")
            digest = hash_string(text)
            print(f"\nSHA-256 hash:\n{digest}\n")

        elif choice == "2":
            file_path = input("Enter the file path: ").strip()
            try:
                digest = hash_file(file_path)
                print(f"\nSHA-256 hash of '{file_path}':\n{digest}\n")
            except FileNotFoundError as e:
                print(e)

        elif choice == "3":
            break
        else:
            print("Invalid choice, please try again.")


# ============================================================
# 2. CAESAR CIPHER
# ============================================================

def caesar_shift_char(ch: str, shift: int) -> str:
    """Shift a single character by 'shift' positions if it is a letter."""
    if "a" <= ch <= "z":
        base = ord("a")
        return chr((ord(ch) - base + shift) % 26 + base)
    elif "A" <= ch <= "Z":
        base = ord("A")
        return chr((ord(ch) - base + shift) % 26 + base)
    else:
        return ch  # Non-letters unchanged


def caesar_encrypt(text: str, shift: int) -> str:
    return "".join(caesar_shift_char(ch, shift) for ch in text)


def caesar_decrypt(text: str, shift: int) -> str:
    # decryption is just shifting backwards
    return caesar_encrypt(text, -shift)


def caesar_menu():
    while True:
        print("\n=== Caesar Cipher ===")
        print("1) Encrypt text")
        print("2) Decrypt text")
        print("3) Back to main menu")
        choice = input("Choose an option (1–3): ").strip()

        if choice in ("1", "2"):
            try:
                shift = int(input("Enter shift value (e.g., 3): ").strip())
            except ValueError:
                print("Shift must be an integer.")
                continue

            text = input("Enter the text: ")

            if choice == "1":
                result = caesar_encrypt(text, shift)
                print(f"\nEncrypted text:\n{result}\n")
            else:
                result = caesar_decrypt(text, shift)
                print(f"\nDecrypted text:\n{result}\n")

        elif choice == "3":
            break
        else:
            print("Invalid choice, please try again.")


# ============================================================
# 3. DIGITAL SIGNATURE (USING OPENSSL)
# ============================================================

def run_openssl_command(args: list, input_data: bytes | None = None):
    """
    Helper to run an openssl command.
    Prints stderr if something goes wrong.
    """
    try:
        result = subprocess.run(
            ["openssl"] + args,
            input=input_data,
            capture_output=True,
            text=False,
            check=False,
        )
    except FileNotFoundError:
        print("Error: OpenSSL not found. Make sure 'openssl' is installed and in your PATH.")
        return None

    if result.returncode != 0:
        print("OpenSSL error:")
        # decode best effort
        print((result.stderr or b"").decode("utf-8", errors="ignore"))
        return None

    return result


def generate_keys(private_key: str = "private_key.pem", public_key: str = "public_key.pem"):
    print(f"\nGenerating RSA private key -> {private_key}")
    res = run_openssl_command(["genrsa", "-out", private_key, "2048"])
    if res is None:
        return

    print(f"Extracting public key -> {public_key}")
    res = run_openssl_command(["rsa", "-in", private_key, "-pubout", "-out", public_key])
    if res is None:
        return

    print("Keys generated successfully.")


def sign_file(message_file: str, private_key: str = "private_key.pem", signature_file: str = "message.sig"):
    if not Path(message_file).is_file():
        print(f"Message file not found: {message_file}")
        return
    if not Path(private_key).is_file():
        print(f"Private key file not found: {private_key}")
        return

    print(f"\nSigning '{message_file}' with '{private_key}' -> {signature_file}")
    res = run_openssl_command(
        ["dgst", "-sha256", "-sign", private_key, "-out", signature_file, message_file]
    )
    if res is None:
        return
    print("File signed successfully.")


def verify_signature(message_file: str, public_key: str = "public_key.pem", signature_file: str = "message.sig"):
    if not Path(message_file).is_file():
        print(f"Message file not found: {message_file}")
        return
    if not Path(public_key).is_file():
        print(f"Public key file not found: {public_key}")
        return
    if not Path(signature_file).is_file():
        print(f"Signature file not found: {signature_file}")
        return

    print(f"\nVerifying signature '{signature_file}' for '{message_file}' using '{public_key}'")
    res = run_openssl_command(
        ["dgst", "-sha256", "-verify", public_key, "-signature", signature_file, message_file]
    )
    if res is None:
        return

    output = (res.stdout or b"").decode("utf-8", errors="ignore").strip()
    print("OpenSSL says:", output)


def digital_signature_menu():
    while True:
        print("\n=== Digital Signature (OpenSSL) ===")
        print("1) Generate RSA key pair")
        print("2) Sign a file")
        print("3) Verify a signature")
        print("4) Back to main menu")
        choice = input("Choose an option (1–4): ").strip()

        if choice == "1":
            priv = input("Private key file name [default: private_key.pem]: ").strip() or "private_key.pem"
            pub = input("Public key file name [default: public_key.pem]: ").strip() or "public_key.pem"
            generate_keys(priv, pub)

        elif choice == "2":
            msg = input("Message file to sign (e.g., message.txt): ").strip()
            priv = input("Private key file [default: private_key.pem]: ").strip() or "private_key.pem"
            sig = input("Signature output file [default: message.sig]: ").strip() or "message.sig"
            sign_file(msg, priv, sig)

        elif choice == "3":
            msg = input("Message file to verify (e.g., message.txt): ").strip()
            pub = input("Public key file [default: public_key.pem]: ").strip() or "public_key.pem"
            sig = input("Signature file [default: message.sig]: ").strip() or "message.sig"
            verify_signature(msg, pub, sig)

        elif choice == "4":
            break
        else:
            print("Invalid choice, please try again.")


# ============================================================
# MAIN MENU
# ============================================================

def main():
    while True:
        print("\n==============================")
        print("   CRYPTO TOOLKIT (Python)    ")
        print("==============================")
        print("1) SHA-256 hashing")
        print("2) Caesar cipher")
        print("3) Digital signature (OpenSSL)")
        print("4) Quit")
        choice = input("Choose an option (1–4): ").strip()

        if choice == "1":
            sha256_menu()
        elif choice == "2":
            caesar_menu()
        elif choice == "3":
            digital_signature_menu()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
