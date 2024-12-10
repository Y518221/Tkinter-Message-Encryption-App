"""
******************************************************
* Project Name: Tkinter Message Encryption App
* Description: A Tkinter-based encryption application that mimics a phone screen interface for a user-friendly experience.
* Author: Yassine Selmi
* LinkedIn: https://www.linkedin.com/in/yassine-selmi-1ba600260/
* Email: [yassineselmi629@gmail.com]
* GitHub: [https://github.com/Y518221]
* Version: 1.0.0

* Features:
    - Encrypts and decrypts text using secure encryption algorithms.
    - Minimalistic and intuitive GUI inspired by mobile phone layouts.
    - Allows users to securely store sensitive information.
    - Built with Python and Tkinter for cross-platform compatibility.

* Usage Instructions:
    1. Run the program using Python 3.8+.
    2. Enter the text to encrypt/decrypt in the designated field.
    3. Click the respective button to process the text.
    4. Save the encrypted/decrypted text for later use.

* Notes:
    - Encryption algorithms used: [Specify algorithms, e.g., AES, RSA, etc.]
    - Always keep your encryption key secure to avoid unauthorized access.
    - The app is meant for educational and personal use only.

* Acknowledgments:
    - Thanks to the open-source community for inspiring the development of this project.

******************************************************
"""

import tkinter as tk
from tkinter import messagebox
import base64
import json
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import pyperclip  # Import pyperclip to copy text to clipboard

users_db = {}
encrypted_messages_db = {}

def save_data():
    with open("data.json", "w") as file:
        json.dump({
            "users": {k: base64.b64encode(v).decode() for k, v in users_db.items()},
            "messages": encrypted_messages_db
        }, file)

def load_data():
    global users_db, encrypted_messages_db
    try:
        with open("data.json", "r") as file:
            data = json.load(file)
            users_db = {k: base64.b64decode(v) for k, v in data["users"].items()}
            encrypted_messages_db = {k: (v if isinstance(v, list) else [v]) for k, v in data["messages"].items()}
    except FileNotFoundError:
        users_db = {}
        encrypted_messages_db = {}

# Hash and encryption functions
def hash_password(password, username):
    key = hashlib.sha256(username.encode()).digest()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encrypted_password = salt + kdf.derive(password.encode())
    return encrypted_password

def verify_password(stored_password, password, username):
    key = hashlib.sha256(username.encode()).digest()
    salt = stored_password[:16]
    stored_key = stored_password[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), stored_key)
        return True
    except Exception:
        return False

def encrypt_message(message, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + (16 - len(message) % 16) * ' '
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + ciphertext).decode()

def decrypt_message(encrypted_message, password):
    encrypted_data = base64.b64decode(encrypted_message)
    salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    return padded_message.decode().rstrip()

# Register User
def register_user():
    username = entry_username.get()
    password = entry_password.get()
    if username and password:
        users_db[username] = hash_password(password, username)
        messagebox.showinfo("Success", f"User {username} registered successfully!")
    else:
        messagebox.showerror("Error", "Please enter a valid username and password.")

# Login User
def login_user():
    username = entry_username.get()
    password = entry_password.get()
    if username in users_db and verify_password(users_db[username], password, username):
        messagebox.showinfo("Success", f"Welcome back, {username}!")
        login_frame.pack_forget()
        message_frame.pack()
    else:
        messagebox.showerror("Error", "Invalid username or password.")

# Encrypt and Display Message
def encrypt_user_message():
    username = entry_username.get()
    password = entry_password.get()
    message = entry_message.get()
    
    if username and password and message:
        # Encrypt the message
        encrypted_message = encrypt_message(message, password)
        
        # Ensure that the username exists in the encrypted_messages_db and its value is a list
        if username not in encrypted_messages_db:
            encrypted_messages_db[username] = []

        # Check if the message already exists in the list of encrypted messages
        existing_message_index = -1
        for i, msg in enumerate(encrypted_messages_db[username]):
            if decrypt_message(msg, password) == message:  # If the decrypted message matches the original one
                existing_message_index = i
                break

        if existing_message_index >= 0:
            # Replace the old encrypted message with the new one
            encrypted_messages_db[username][existing_message_index] = encrypted_message
        else:
            # Add the new encrypted message to the list
            encrypted_messages_db[username].append(encrypted_message)
        
        save_data()
        
        label_encrypted_message.config(text=f"Encrypted: {encrypted_message}")
        encrypted_message_global.set(encrypted_message)  # Store the encrypted message in the global variable
    else:
        messagebox.showerror("Error", "Please enter a valid username, password, and message.")

# Decrypt and Display Message (Handle multiple encrypted messages)
def decrypt_user_message():
    username = entry_username.get()
    password = entry_password.get()
    encrypted_message = entry_encrypted_message.get()  # Get the encrypted message input by the user

    if username in encrypted_messages_db:
        # Check if the encrypted message matches any of the stored encrypted messages
        stored_encrypted_messages = encrypted_messages_db[username]
        
        if encrypted_message in stored_encrypted_messages:  # Ensure the message matches one of the stored ones
            if password:
                decrypted_message = decrypt_message(encrypted_message, password)
                label_decrypted_message.config(text=f"Decrypted: {decrypted_message}")
            else:
                messagebox.showerror("Error", "Please enter a password to decrypt the message.")
        else:
            messagebox.showerror("Error", "Encrypted message not found or tampered with.")
    else:
        messagebox.showerror("Error", "No encrypted message found for this user.")

# Variable to store the encrypted message for copying
def copy_encrypted_message():
    encrypted_message = encrypted_message_global.get()  # Get the encrypted message from the global variable
    if encrypted_message:
        window.clipboard_clear()
        window.clipboard_append(encrypted_message)
        messagebox.showinfo("Success", "Encrypted message copied to clipboard.")
    else:
        messagebox.showerror("Error", "No encrypted message to copy.")

# Go back to login screen and clear fields
def go_back_to_login():
    entry_username.delete(0, tk.END)  # Clear username field
    entry_password.delete(0, tk.END)  # Clear password field
    entry_message.delete(0, tk.END)  # Clear message field
    entry_encrypted_message.delete(0, tk.END)  # Clear encrypted message field
    label_encrypted_message.config(text="Encrypted:")  # Clear encrypted message label
    label_decrypted_message.config(text="Decrypted:")  # Clear decrypted message label
    message_frame.pack_forget()
    login_frame.pack()

# Clear all encrypted messages with a confirmation message
def clear_all_messages():
    username = entry_username.get()  # Get the current username
    if username in encrypted_messages_db:
        result = messagebox.askyesno(
            "Confirm", 
            f"Are you sure you want to delete all messages for {username}? This action cannot be undone, Only the messages will be deleted, not the usernames or passwords."
        )
        if result:
            encrypted_messages_db[username] = []  # Clear only the messages for the current user
            save_data()
            messagebox.showinfo("Success", f"All messages for {username} have been deleted.")
    else:
        messagebox.showerror("Error", f"No messages found for {username}.")

# Create main window (phone-like screen)
window = tk.Tk()
window.title("Message Encryption App")
window.geometry("360x640")  # Phone screen size (portrait mode)
window.resizable(False, False)  # Prevent resizing the window

# Background Color
window.configure(bg="#f5f5f5")

# Variable to store the encrypted message for copying
encrypted_message_global = tk.StringVar()

# Login Frame
login_frame = tk.Frame(window, bg="#f5f5f5")

label_username = tk.Label(login_frame, text="Username", font=("Arial", 14), bg="#f5f5f5")
label_username.pack(pady=10)

entry_username = tk.Entry(login_frame, font=("Arial", 14), width=20)
entry_username.pack(pady=5)

label_password = tk.Label(login_frame, text="Password", font=("Arial", 14), bg="#f5f5f5")
label_password.pack(pady=10)

entry_password = tk.Entry(login_frame, show="*", font=("Arial", 14), width=20)
entry_password.pack(pady=5)

btn_login = tk.Button(login_frame, text="Login", font=("Arial", 14), command=login_user, width=20, height=2, bg="#4CAF50", fg="white", relief="flat")
btn_login.pack(pady=20)

btn_register = tk.Button(login_frame, text="Register", font=("Arial", 14), command=register_user, width=20, height=2, bg="#008CBA", fg="white", relief="flat")
btn_register.pack(pady=10)

login_frame.pack()

# Message Frame

message_frame = tk.Frame(window, bg="#f5f5f5")

label_message = tk.Label(message_frame, text="Enter Message", font=("Arial", 14), bg="#f5f5f5")
label_message.pack(pady=10)

entry_message = tk.Entry(message_frame, font=("Arial", 14), width=20)
entry_message.pack(pady=5)

btn_encrypt = tk.Button(message_frame, text="Encrypt", font=("Arial", 14), command=encrypt_user_message, width=20, height=2, bg="#4CAF50", fg="white", relief="flat")
btn_encrypt.pack(pady=10)

label_encrypted_message = tk.Label(message_frame, text="Encrypted:", font=("Arial", 14), bg="#f5f5f5")
label_encrypted_message.pack(pady=10)

btn_copy = tk.Button(message_frame, text="Copy Encrypted", font=("Arial", 14), command=copy_encrypted_message, width=20, height=2, bg="#FFD700", fg="white", relief="flat")
btn_copy.pack(pady=10)

label_decrypted_message = tk.Label(message_frame, text="Decrypted:", font=("Arial", 14), bg="#f5f5f5", wraplength=300)
label_decrypted_message.pack(pady=5)

entry_encrypted_message = tk.Entry(message_frame, font=("Arial", 14), width=20)
entry_encrypted_message.pack(pady=5)

btn_decrypt = tk.Button(message_frame, text="Decrypt", font=("Arial", 14), command=decrypt_user_message, width=20, height=2, bg="#FF6347", fg="white", relief="flat")
btn_decrypt.pack(pady=10)

btn_clear_messages = tk.Button(message_frame, text="Clear All Messages", font=("Arial", 14), command=clear_all_messages, width=20, height=2, bg="#FF6347", fg="white", relief="flat")
btn_clear_messages.pack(pady=10)

btn_back = tk.Button(message_frame, text="Back to Login", font=("Arial", 14), command=go_back_to_login, width=20, height=2, bg="#FF5733", fg="white", relief="flat")
btn_back.pack(pady=10)

# Start by loading existing data (users and encrypted messages)
load_data()

# Start the app
window.mainloop()
