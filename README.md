# 🎵 Audio-Steganography-GUI-Tool 🔐

A Python-based **Audio Steganography GUI Tool** that allows you to **encrypt a hidden message** and embed it inside a **16-bit WAV audio file**, and later **extract + decrypt** it using a password.
The project uses **Fernet encryption**, **PBKDF2-HMAC key derivation**, and **LSB audio steganography implemented** inside a Tkinter GUI.

---

## 🧱 Project Structure

```bash
Audio-Steganography-GUI-Tool/
│
├── audio_steganography.py     # Main GUI application
└── README.md                  # Project documentation
```
---

## ✨ Features

#### 🔐 Encryption & Embedding

- Encrypts message using **Fernet (AES-128 authenticated encryption)**
- Derives key from password using **PBKDF2-HMAC (SHA256)**
- Embeds encrypted payload into WAV audio using **LSB (Least Significant Bit)**

#### 🔓 Extraction & Decryption

- Extracts embedded payload from WAV
- Uses stored salt to regenerate the Fernet key
- Decrypts message securely
- Shows the recovered message inside the GUI

#### 🖥 GUI Highlights

- Simple and clean **Tkinter interface**
- Load WAV files
- Load message from `.txt`
- Save stego audio output
- Error handling + status updates

---

## 🛠 Technologies Used

| Technology                             | Role                      |
| -------------------------------------- | ------------------------- |
| **Python 3**                           | Main language             |
| **Tkinter**                            | GUI                       |
| **wave module**                        | WAV file operations       |
| **array module**                       | Audio sample manipulation |
| **cryptography (Fernet + PBKDF2HMAC)** | Encryption                |
| **LSB Steganography**                  | Data embedding            |

---

## 📌 Requirements

Make sure you install required dependencies:

```bash
pip install cryptography
```

Standard libraries like `wave`, `array`, `tkinter`, `base64`, and `struct` are already included with Python.

---

## ▶️ How to Run

**1. Clone the repository:**

```bash
git clone https://github.com/ShakalBhau0001/Audio-Steganography-GUI-Tool.git
```

**2. Enter the project folder:**

```bash
cd Audio-Steganography-GUI-Tool
```

**3. Run the GUI:**

```bash
python audio_steganography.py
```

---

## 📁 Supported File Format

- **Input (Carrier):** 16-bit PCM **WAV** only
- **Output (Stego Audio):** WAV
- **Message Input:** Text or `.txt` file

> ⚠️ If audio is not 16-bit PCM, the app will reject it.

---

## ⚙️ How It Works

**1️⃣ Key Derivation**

- Password → PBKDF2-HMAC(SHA256, 390k iterations) → 32-byte key → Fernet key

**2️⃣ Encryption**

- Message → `f.encrypt()` → Encrypted bytes
- Stored with:
    - 4-byte magic header (`AUDS`)
    - 16-byte salt
    - 4-byte encrypted length
    - Encrypted payload

**3️⃣ Embedding**

- Payload bits are inserted into **LSB of audio samples.**

**4️⃣ Extraction**

- Reads LSB bits
- Reconstructs payload
- Validates header
- Re-derives Fernet key
- Decrypts message

---

## 🌟 Future Enhancements

- Add support for larger audio files
- Add progress bar during embedding
- Add message file export option
- Improve error handling for corrupted audio
- Add option for binary file hiding

---

## 📦 Extended Version

This repository focuses on a specific steganography technique and is designed
**for learning and experimentation**.

For a **more advanced and combined implementation** that includes
image and audio steganography with file encryption support, refer to:

 🔗 **[StegaVault-GUI](https://github.com/ShakalBhau0001/StegaVault-GUI)**

---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**.
It is not designed to provide real-world secure communication. 
Steganography alone does not guarantee secrecy.

---

## 🪪 Author

> **Creator: Shakal Bhau**

> **GitHub: [ShakalBhau0001](https://github.com/ShakalBhau0001)**

---
