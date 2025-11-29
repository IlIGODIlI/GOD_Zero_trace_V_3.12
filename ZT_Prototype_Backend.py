import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import tkinter as tk
from tkinter import filedialog,messagebox

# ----------------------------------------------------------------------
# AES ENCRYPT FUNCTION  (MODULAR)
# ----------------------------------------------------------------------

def encrypt_file(file_path):
    """
    Encrypts a file using AES-256-CBC.
    Returns: encrypted_file_path, encryption_key (base64)
    """

    # Generate AES key (32 bytes) and IV (16 bytes)
    key = os.urandom(32)
    iv = os.urandom(16)

    # Read file data
    with open(file_path, "rb") as f:
        data = f.read()

    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Replace original file with IV + encrypted bytes
    with open(file_path, "wb") as f:
        f.write(iv + encrypted_data)

    # Return encrypted file path + base64 key so the user can store it
    encoded_key = base64.b64encode(key).decode("utf-8")
    return file_path, encoded_key


# ----------------------------------------------------------------------
# SECURE DELETE FUNCTION
# ----------------------------------------------------------------------

def secure_delete(file_path):
    """
    Securely deletes a file by overwriting it with random bytes
    before deleting it.
    """

    if not os.path.exists(file_path):
        return False, "File not found."

    size = os.path.getsize(file_path)

    # Overwrite with random bytes
    with open(file_path, "wb") as f:
        f.write(os.urandom(size))

    # Delete file
    os.remove(file_path)

    return True, f"'{os.path.basename(file_path)}' securely deleted."


# ----------------------------------------------------------------------
# AES DECRYPT FUNCTION (MODULAR)
# ----------------------------------------------------------------------

def decrypt_file(file_path, key_b64):
    """
    Decrypts an AES-256-CBC encrypted file.
    User must provide base64-encoded key.
    """

    key = base64.b64decode(key_b64)

    # Read encrypted data
    with open(file_path, "rb") as f:
        file_data = f.read()

    # First 16 bytes are IV
    iv = file_data[:16]
    encrypted_data = file_data[16:]

    # Decrypt AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plain_data = unpadder.update(padded_plain) + unpadder.finalize()

    # Write decrypted data back into the file
    with open(file_path, "wb") as f:
        f.write(plain_data)

    return True, f"'{os.path.basename(file_path)}' successfully decrypted."


# ----------------------------------------------------------------------
# USER CHOICE HANDLER (NO GUI YET)
# ----------------------------------------------------------------------

def encrypt_with_user_choice(file_path):
    """
    Encrypts a file, then asks whether user wants secure deletion.
    If YES: delete file & discard key
    If NO: return key to user
    """

    encrypted_path, key = encrypt_file(file_path)

    # Ask the user about secure deletion (text mode, GUI later)
    choice = input("Secure delete the original file? (y/n): ").lower()

    if choice == "y":
        secure_delete(encrypted_path)
        return True, "File encrypted, key destroyed, file securely deleted."
    else:
        return True, f"File encrypted.\nSAVE THIS KEY:\n{key}"


# ----------------------------------------------------------------------
# READY FOR GUI INTEGRATION
# ----------------------------------------------------------------------
 
 #Main GUI interface

        