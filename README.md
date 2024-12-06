# Message Encryption App

This is a Tkinter-based message encryption application that allows users to register, login, encrypt, decrypt messages, and store them securely. The application uses AES encryption and PBKDF2 key derivation for securely encrypting and decrypting messages.

## Features:
- **User Registration and Login:** Users can register with a username and password, and then log in to access the message encryption functionality.
- **Message Encryption:** Users can encrypt their messages using a password, and the application securely stores the encrypted messages.
- **Message Decryption:** Users can decrypt their encrypted messages by entering their password.
- **Clipboard Copy:** Users can copy the encrypted message to the clipboard for easy sharing.
- **Clear All Messages:** Users can clear all encrypted messages for a specific username.

## Technologies Used:
- Python 3
- Tkinter for GUI
- Cryptography (AES encryption, PBKDF2 for password hashing)
- JSON for storing user data and encrypted messages
- Pyperclip for copying messages to clipboard

## License:
This project is licensed under the **Proprietary License**. You are not allowed to copy, distribute, or use the code for commercial purposes without permission.

## Requirements:
- Python 3.x
- cryptography library
- pyperclip library

You can install the required libraries by running:

```bash
pip install cryptography pyperclip
