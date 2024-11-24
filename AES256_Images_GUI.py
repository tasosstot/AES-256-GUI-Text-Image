import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import os

# Constants
BLOCK_SIZE = 16
PAD = "{"
FORMAT = "BMP"

# IV and Counter initialization
iv_ctr = os.urandom(32)
ctr = Counter.new(128)
iv = os.urandom(16)

# Output filenames
filename_encrypted_ecb = "encrypted_ecb"
filename_decrypted_ecb = "decrypted_ecb"
filename_encrypted_cbc = "encrypted_cbc"
filename_decrypted_cbc = "decrypted_cbc"
filename_encrypted_ctr = "encrypted_ctr"
filename_decrypted_ctr = "decrypted_ctr"

# Initialize Tkinter
root = tk.Tk()
root.title("Image Encryption/Decryption")

# Global variables
hkey = None

# Padding for images
def pad_img(data):
    return data + b"\x00" * (16 - len(data) % 16)

# Convert pixel data back to RGB
def trans_format_RGB(data):
    red, green, blue = tuple(map(lambda e: [data[i] for i in range(len(data)) if i % 3 == e], [0, 1, 2]))
    return tuple(zip(red, green, blue))

# Generate hashed key
def hash_key():
    global hkey
    key = e_key.get()
    hash_obj = SHA256.new(key.encode("utf-8"))
    hkey = hash_obj.digest()
    hash_key_label.config(text=f"Generated Key: {hkey.hex()}")

# Encrypt image with ECB
def encrypt_image_ecb(filename):
    im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()
    imlength = len(value_vector)
    aesCipher_ECB = AES.new(hkey, AES.MODE_ECB)
    cipher_vector = aesCipher_ECB.encrypt(pad_img(value_vector)[:imlength])
    cipher_img = trans_format_RGB(cipher_vector)
    im2 = Image.new(im.mode, im.size)
    im2.putdata(cipher_img)
    im2.save(filename_encrypted_ecb + "." + FORMAT, FORMAT)

# Decrypt image with ECB
def decrypt_image_ecb(filename):
    im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()
    imlength = len(value_vector)
    aesDecipher_ECB = AES.new(hkey, AES.MODE_ECB)
    decipher_vector = aesDecipher_ECB.decrypt(pad_img(value_vector)[:imlength])
    decipher_img = trans_format_RGB(decipher_vector)
    im2 = Image.new(im.mode, im.size)
    im2.putdata(decipher_img)
    im2.save(filename_decrypted_ecb + "." + FORMAT, FORMAT)

# Encrypt image with CBC
def encrypt_image_cbc(filename):
    im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()
    imlength = len(value_vector)
    aesCipher_CBC = AES.new(hkey, AES.MODE_CBC, iv)
    cipher_vector = aesCipher_CBC.encrypt(pad_img(value_vector)[:imlength])
    cipher_img = trans_format_RGB(cipher_vector)
    im2 = Image.new(im.mode, im.size)
    im2.putdata(cipher_img)
    im2.save(filename_encrypted_cbc + "." + FORMAT, FORMAT)

# Decrypt image with CBC
def decrypt_image_cbc(filename):
    im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()
    imlength = len(value_vector)
    aesDecipher_CBC = AES.new(hkey, AES.MODE_CBC, iv)
    decipher_vector = aesDecipher_CBC.decrypt(pad_img(value_vector)[:imlength])
    decipher_img = trans_format_RGB(decipher_vector)
    im2 = Image.new(im.mode, im.size)
    im2.putdata(decipher_img)
    im2.save(filename_decrypted_cbc + "." + FORMAT, FORMAT)

# Encrypt image with CTR
def encrypt_image_ctr(filename):
    im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()
    imlength = len(value_vector)
    aesCipher_CTR = AES.new(iv_ctr, AES.MODE_CTR, counter=ctr)
    cipher_vector = aesCipher_CTR.encrypt(pad_img(value_vector)[:imlength])
    cipher_img = trans_format_RGB(cipher_vector)
    im2 = Image.new(im.mode, im.size)
    im2.putdata(cipher_img)
    im2.save(filename_encrypted_ctr + "." + FORMAT, FORMAT)

# Decrypt image with CTR
def decrypt_image_ctr(filename):
    im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()
    imlength = len(value_vector)
    aesCipher_CTR = AES.new(iv_ctr, AES.MODE_CTR, counter=ctr)
    decipher_vector = aesCipher_CTR.decrypt(pad_img(value_vector)[:imlength])
    decipher_img = trans_format_RGB(decipher_vector)
    im2 = Image.new(im.mode, im.size)
    im2.putdata(decipher_img)
    im2.save(filename_decrypted_ctr + "." + FORMAT, FORMAT)

# GUI Functions
def load_image_for_encryption():
    file_path = filedialog.askopenfilename(title="Select an Image")
    if file_path:
        encrypt_image_ecb(file_path)
        encrypt_image_cbc(file_path)
        encrypt_image_ctr(file_path)

def load_image_for_decryption_ecb():
    file_path = filedialog.askopenfilename(title="Select Encrypted Image (ECB)")
    if file_path:
        decrypt_image_ecb(file_path)

def load_image_for_decryption_cbc():
    file_path = filedialog.askopenfilename(title="Select Encrypted Image (CBC)")
    if file_path:
        decrypt_image_cbc(file_path)

def load_image_for_decryption_ctr():
    file_path = filedialog.askopenfilename(title="Select Encrypted Image (CTR)")
    if file_path:
        decrypt_image_ctr(file_path)

# GUI Layout
e_key = tk.Entry(root, width=40, borderwidth=5)
e_key.grid(row=0, column=0, padx=10, pady=10)
e_key.insert(0, "Enter encryption key")

tk.Button(root, text="Generate Key", command=hash_key).grid(row=0, column=1, padx=10, pady=10)

hash_key_label = tk.Label(root, text="Generated Key: None", fg="blue")
hash_key_label.grid(row=1, column=0, columnspan=2, pady=5)

tk.Button(root, text="Encrypt Image", command=load_image_for_encryption).grid(row=2, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt Image (ECB)", command=load_image_for_decryption_ecb).grid(row=3, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt Image (CBC)", command=load_image_for_decryption_cbc).grid(row=4, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt Image (CTR)", command=load_image_for_decryption_ctr).grid(row=5, column=0, padx=10, pady=10)

# Run the application
root.mainloop()
