import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import os

# Initialize the Tkinter root window
root = tk.Tk()
root.title("Encryption/Decryption")

# Frames for layout
cip_frame = tk.LabelFrame(root, text="Cipher Texts", padx=5, pady=5)
cip_frame.grid(row=5, column=0, padx=20, pady=10)

key_frame = tk.LabelFrame(root, text="Generated Hash Key", padx=5, pady=5)
key_frame.grid(row=3, column=0, padx=20, pady=10)

decrypt_frame = tk.LabelFrame(root, text="Decrypted Texts", padx=5, pady=5)
decrypt_frame.grid(row=6, column=0, padx=20, pady=10)

# AES Parameters
BLOCK_SIZE = 16
iv = os.urandom(16)
ctr = Counter.new(128)

# Text Entries
e_key = tk.Entry(root, width=40, borderwidth=5)
e_key.grid(row=0, column=0, padx=20, pady=10)
e_key.insert(0, "Type your Key")

e_plain = tk.Entry(root, width=40, borderwidth=5)
e_plain.grid(row=1, column=0, padx=20, pady=10)
e_plain.insert(0, "Type Plain Text")

# Text boxes for cipher texts, decrypted texts, and hash key
ecb_cipher_text_box = tk.Text(cip_frame, height=2, width=30, borderwidth=5)
cbc_cipher_text_box = tk.Text(cip_frame, height=2, width=30, borderwidth=5)
ctr_cipher_text_box = tk.Text(cip_frame, height=2, width=30, borderwidth=5)

hash_key_box = tk.Text(key_frame, height=5, width=20, borderwidth=5)

ecb_decrypt_text_box = tk.Text(decrypt_frame, height=2, width=30, borderwidth=5)
cbc_decrypt_text_box = tk.Text(decrypt_frame, height=2, width=30, borderwidth=5)
ctr_decrypt_text_box = tk.Text(decrypt_frame, height=2, width=30, borderwidth=5)

# Place the text boxes in the GUI
ecb_cipher_text_box.grid(row=0, column=0, padx=10, pady=5)
cbc_cipher_text_box.grid(row=1, column=0, padx=10, pady=5)
ctr_cipher_text_box.grid(row=2, column=0, padx=10, pady=5)

hash_key_box.grid(row=0, column=0, padx=10, pady=5)

ecb_decrypt_text_box.grid(row=0, column=0, padx=10, pady=5)
cbc_decrypt_text_box.grid(row=1, column=0, padx=10, pady=5)
ctr_decrypt_text_box.grid(row=2, column=0, padx=10, pady=5)

# Initialize the hashed key
hkey = b""


# Generate the hashed key
def hash_key():
    global hkey
    key = e_key.get()
    hash_obj = SHA256.new(key.encode("utf-8"))
    hkey = hash_obj.digest()
    hash_key_box.delete(1.0, tk.END)  # Clear text box
    hash_key_box.insert(tk.END, hkey.hex())  # Show hashed key


# AES Encryption and Decryption Functions for Text
def encryptor_ECB(msg):
    aesCipher_ECB = AES.new(hkey, AES.MODE_ECB)
    padded_msg = pad(msg.encode("utf-8"), BLOCK_SIZE)
    cipher_text = aesCipher_ECB.encrypt(padded_msg)
    return cipher_text


def decryptor_ECB(cipher):
    aesDecipher_ECB = AES.new(hkey, AES.MODE_ECB)
    decrypted_msg = unpad(aesDecipher_ECB.decrypt(cipher), BLOCK_SIZE).decode("utf-8")
    return decrypted_msg


def encryptor_CBC(msg):
    aesCipher_CBC = AES.new(hkey, AES.MODE_CBC, iv)
    padded_msg = pad(msg.encode("utf-8"), BLOCK_SIZE)
    cipher_text = aesCipher_CBC.encrypt(padded_msg)
    return cipher_text


def decryptor_CBC(cipher):
    aesDecipher_CBC = AES.new(hkey, AES.MODE_CBC, iv)
    decrypted_msg = unpad(aesDecipher_CBC.decrypt(cipher), BLOCK_SIZE).decode("utf-8")
    return decrypted_msg


def encryptor_CTR(msg):
    aesCipher_CTR = AES.new(hkey, AES.MODE_CTR, counter=ctr)
    cipher_text = aesCipher_CTR.encrypt(msg.encode("utf-8"))
    return cipher_text


def decryptor_CTR(cipher):
    aesDecipher_CTR = AES.new(hkey, AES.MODE_CTR, counter=ctr)
    decrypted_msg = aesDecipher_CTR.decrypt(cipher).decode("utf-8")
    return decrypted_msg


# Encrypt Text in All Modes and Display Cipher Texts
def encrypt_text():
    msg = e_plain.get()
    ecb_cipher = encryptor_ECB(msg)
    cbc_cipher = encryptor_CBC(msg)
    ctr_cipher = encryptor_CTR(msg)

    ecb_cipher_text_box.delete(1.0, tk.END)
    ecb_cipher_text_box.insert(tk.END, f"ECB: {ecb_cipher.hex()}")

    cbc_cipher_text_box.delete(1.0, tk.END)
    cbc_cipher_text_box.insert(tk.END, f"CBC: {cbc_cipher.hex()}")

    ctr_cipher_text_box.delete(1.0, tk.END)
    ctr_cipher_text_box.insert(tk.END, f"CTR: {ctr_cipher.hex()}")


# Decrypt Text in All Modes and Display Plaintexts
def decrypt_ecb():
    cipher_hex = ecb_cipher_text_box.get(1.0, tk.END).strip().replace("ECB: ", "")
    if cipher_hex:
        cipher_bytes = bytes.fromhex(cipher_hex)
        plaintext = decryptor_ECB(cipher_bytes)
        ecb_decrypt_text_box.delete(1.0, tk.END)
        ecb_decrypt_text_box.insert(tk.END, plaintext)


def decrypt_cbc():
    cipher_hex = cbc_cipher_text_box.get(1.0, tk.END).strip().replace("CBC: ", "")
    if cipher_hex:
        cipher_bytes = bytes.fromhex(cipher_hex)
        plaintext = decryptor_CBC(cipher_bytes)
        cbc_decrypt_text_box.delete(1.0, tk.END)
        cbc_decrypt_text_box.insert(tk.END, plaintext)


def decrypt_ctr():
    cipher_hex = ctr_cipher_text_box.get(1.0, tk.END).strip().replace("CTR: ", "")
    if cipher_hex:
        cipher_bytes = bytes.fromhex(cipher_hex)
        plaintext = decryptor_CTR(cipher_bytes)
        ctr_decrypt_text_box.delete(1.0, tk.END)
        ctr_decrypt_text_box.insert(tk.END, plaintext)


# Buttons
tk.Button(root, text="Generate Key", command=hash_key).grid(row=0, column=1, padx=10, pady=5)
tk.Button(root, text="Encrypt Text", command=encrypt_text).grid(row=1, column=1, padx=10, pady=5)

tk.Button(root, text="Decrypt ECB", command=decrypt_ecb).grid(row=5, column=1, padx=10, pady=5)
tk.Button(root, text="Decrypt CBC", command=decrypt_cbc).grid(row=6, column=1, padx=10, pady=5)
tk.Button(root, text="Decrypt CTR", command=decrypt_ctr).grid(row=7, column=1, padx=10, pady=5)

# Run the application
root.mainloop()
