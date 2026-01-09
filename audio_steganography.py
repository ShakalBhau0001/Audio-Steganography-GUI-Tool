import os
import struct
import secrets
import base64
import wave
import sys
from array import array
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Key derivation for Fernet


def derive_fernet_key_from_password(
    password: str, salt: bytes, iterations: int = 390000
) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)


# Bit utilities


def bytes_to_bits(data: bytes):
    for b in data:
        for i in range(7, -1, -1):
            yield (b >> i) & 1


def bits_to_bytes(bits):
    out = bytearray()
    bit_iter = iter(bits)
    while True:
        byte = 0
        try:
            for _ in range(8):
                bit = next(bit_iter)
                byte = (byte << 1) | (bit & 1)
        except StopIteration:
            break
        out.append(byte)
    return bytes(out)


# Payload format

MAGIC = b"AUDS"  # audio magic


def make_payload(encrypted_bytes: bytes, salt: bytes) -> bytes:
    return MAGIC + salt + struct.pack(">I", len(encrypted_bytes)) + encrypted_bytes


def parse_payload(raw: bytes):
    if len(raw) < 24:
        raise ValueError("Payload too small or corrupted.")
    if raw[:4] != MAGIC:
        raise ValueError("MAGIC header not found. No payload here.")
    salt = raw[4:20]
    enc_len = struct.unpack(">I", raw[20:24])[0]
    if len(raw) < 24 + enc_len:
        raise ValueError("Payload length mismatch / corrupted payload.")
    encrypted_bytes = raw[24 : 24 + enc_len]
    return salt, encrypted_bytes


# WAV LSB steganography functions (PCM 16-bit)


def capacity_in_bytes(wav_path: str) -> int:
    with wave.open(wav_path, "rb") as wf:
        n_frames = wf.getnframes()
        n_channels = wf.getnchannels()
    bits = n_frames * n_channels
    return bits // 8


def embed_payload_in_wav(input_wav_path: str, payload: bytes, output_wav_path: str):
    with wave.open(input_wav_path, "rb") as wf:
        params = wf.getparams()
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        n_frames = wf.getnframes()
        frames = wf.readframes(n_frames)

    if sampwidth != 2:
        raise ValueError("Only 16-bit PCM WAV files are supported. (sampwidth != 2)")

    total_samples = n_frames * n_channels
    bits_needed = len(payload) * 8
    if bits_needed > total_samples:
        raise ValueError(
            f"Payload too large. Need {bits_needed} bits, WAV supplies {total_samples} bits."
        )

    # Convert frames to array
    samples = array("h")
    samples.frombytes(frames)

    if sys.byteorder == "big":
        samples.byteswap()

    # Embed bits into LSB of each sample
    bit_iter = bytes_to_bits(payload)
    for i in range(len(samples)):
        try:
            b = next(bit_iter)
            samples[i] = (samples[i] & ~1) | b
        except StopIteration:
            break

    # Convert back to bytes
    out_frames = samples.tobytes()
    if sys.byteorder == "big":
        out_array = array("h")
        out_array.frombytes(out_frames)
        out_array.byteswap()
        out_frames = out_array.tobytes()

    # Write output WAV with same params
    with wave.open(output_wav_path, "wb") as out_wf:
        out_wf.setparams(params)
        out_wf.writeframes(out_frames)


def extract_payload_from_wav(stego_wav_path: str, payload_length_bytes: int) -> bytes:
    with wave.open(stego_wav_path, "rb") as wf:
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        n_frames = wf.getnframes()
        frames = wf.readframes(n_frames)

    if sampwidth != 2:
        raise ValueError("Only 16-bit PCM WAV files are supported for extraction.")

    samples = array("h")
    samples.frombytes(frames)

    import sys

    if sys.byteorder == "big":
        samples.byteswap()

    total_samples = len(samples)
    bits_required = payload_length_bytes * 8
    if bits_required > total_samples:
        raise ValueError(
            "WAV does not contain enough embedded bits to extract requested payload."
        )

    bits = []
    for i in range(bits_required):
        bits.append(samples[i] & 1)

    return bits_to_bytes(bits)


# High-level encrypt and decrypt


def encrypt_message_and_embed(
    wav_path: str, message_bytes: bytes, password: str, output_wav_path: str
):
    salt = secrets.token_bytes(16)
    key = derive_fernet_key_from_password(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(message_bytes)
    payload = make_payload(encrypted, salt)
    embed_payload_in_wav(wav_path, payload, output_wav_path)


def extract_and_decrypt(stego_wav_path: str, password: str):
    # First, extract header bytes to get payload length
    header_bytes = extract_payload_from_wav(stego_wav_path, 24)
    if header_bytes[:4] != MAGIC:
        raise ValueError("No valid payload found (MAGIC mismatch).")
    salt = header_bytes[4:20]
    enc_len = struct.unpack(">I", header_bytes[20:24])[0]

    # Extract full payload
    full_payload = extract_payload_from_wav(stego_wav_path, 24 + enc_len)
    salt2, encrypted_bytes = parse_payload(full_payload)
    if salt != salt2:
        raise ValueError("Internal payload corruption (salt mismatch).")

    key = derive_fernet_key_from_password(password, salt)
    f = Fernet(key)
    try:
        decrypted = f.decrypt(encrypted_bytes)
    except Exception as e:
        raise ValueError(
            "Decryption failed: wrong password or corrupted payload."
        ) from e
    return decrypted


# GUI


class AudioStegApp:
    def __init__(self, root):
        self.root = root
        root.title("Audio Steganography - Encrypt & Embed in WAV")
        root.resizable(False, False)
        pad = 8

        # Top frame
        frame = tk.Frame(root, padx=10, pady=10)
        frame.pack()

        # Encrypt section
        tk.Label(
            frame,
            text="1) Encrypt & Embed Message into WAV",
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w")

        tk.Label(frame, text="Select carrier WAV (16-bit PCM):").grid(
            row=1, column=0, sticky="w", pady=(pad // 2, 0)
        )
        self.enc_wav_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.enc_wav_var, width=50).grid(
            row=1, column=1, sticky="w", pady=(pad // 2, 0)
        )
        tk.Button(frame, text="Browse", command=self.browse_enc_wav).grid(
            row=1, column=2, padx=6, pady=(pad // 2, 0)
        )

        tk.Label(frame, text="Type message to hide:").grid(
            row=2, column=0, sticky="nw", pady=(pad // 2, 0)
        )
        self.msg_text = scrolledtext.ScrolledText(frame, width=40, height=6)
        self.msg_text.grid(row=2, column=1, sticky="w", pady=(pad // 2, 0))

        tk.Button(frame, text="Or load .txt file", command=self.load_txt_file).grid(
            row=2, column=2, sticky="n", padx=6, pady=(pad // 2, 0)
        )

        tk.Label(frame, text="Encryption password:").grid(
            row=3, column=0, sticky="w", pady=(pad // 2, 0)
        )
        self.enc_pass_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.enc_pass_var, show="*", width=30).grid(
            row=3, column=1, sticky="w", pady=(pad // 2, 0)
        )

        tk.Label(frame, text="Output filename (will be WAV):").grid(
            row=4, column=0, sticky="w", pady=(pad // 2, 0)
        )
        self.out_name_var = tk.StringVar(value="stego_output.wav")
        tk.Entry(frame, textvariable=self.out_name_var, width=30).grid(
            row=4, column=1, sticky="w", pady=(pad // 2, 0)
        )
        tk.Button(
            frame,
            text="Encrypt & Embed",
            bg="#2e7d32",
            fg="white",
            command=self.handle_encrypt,
        ).grid(row=4, column=2, padx=6, pady=(pad // 2, 0))

        # Separator
        tk.Label(frame, text="").grid(row=5, column=0, pady=6)

        # Decrypt section
        tk.Label(
            frame,
            text="2) Extract & Decrypt Message from WAV",
            font=("Segoe UI", 11, "bold"),
        ).grid(row=6, column=0, columnspan=3, sticky="w")

        tk.Label(frame, text="Select stego WAV:").grid(
            row=7, column=0, sticky="w", pady=(pad // 2, 0)
        )
        self.dec_wav_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.dec_wav_var, width=50).grid(
            row=7, column=1, sticky="w", pady=(pad // 2, 0)
        )
        tk.Button(frame, text="Browse", command=self.browse_dec_wav).grid(
            row=7, column=2, padx=6, pady=(pad // 2, 0)
        )

        tk.Label(frame, text="Decryption password:").grid(
            row=8, column=0, sticky="w", pady=(pad // 2, 0)
        )
        self.dec_pass_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.dec_pass_var, show="*", width=30).grid(
            row=8, column=1, sticky="w", pady=(pad // 2, 0)
        )

        tk.Button(
            frame,
            text="Extract & Decrypt",
            bg="#1565c0",
            fg="white",
            command=self.handle_decrypt,
        ).grid(row=9, column=1, sticky="w", pady=(pad // 2, 0))

        tk.Label(frame, text="Decrypted message:").grid(
            row=10, column=0, sticky="nw", pady=(pad // 2, 0)
        )
        self.dec_msg_display = scrolledtext.ScrolledText(frame, width=60, height=8)
        self.dec_msg_display.grid(row=10, column=1, columnspan=2, pady=(pad // 2, 0))

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = tk.Label(
            root, textvariable=self.status_var, bd=1, relief="sunken", anchor="w"
        )
        status.pack(fill="x", side="bottom")

    # GUI helpers
    def set_status(self, text: str):
        self.status_var.set(text)
        self.root.update_idletasks()

    def browse_enc_wav(self):
        path = filedialog.askopenfilename(
            title="Select carrier WAV",
            filetypes=[("WAV files", "*.wav"), ("All files", "*.*")],
        )
        if path:
            self.enc_wav_var.set(path)

    def browse_dec_wav(self):
        path = filedialog.askopenfilename(
            title="Select stego WAV",
            filetypes=[("WAV files", "*.wav"), ("All files", "*.*")],
        )
        if path:
            self.dec_wav_var.set(path)

    def load_txt_file(self):
        path = filedialog.askopenfilename(
            title="Select text file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.msg_text.delete("1.0", tk.END)
            self.msg_text.insert(tk.END, content)
            self.set_status(f"Loaded message from {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read text file: {e}")
            self.set_status("Failed to load text file")

    # Handlers
    def handle_encrypt(self):
        wav_path = self.enc_wav_var.get().strip()
        password = self.enc_pass_var.get()
        out_name = self.out_name_var.get().strip()
        msg = self.msg_text.get("1.0", tk.END).rstrip("\n")

        if not wav_path:
            messagebox.showwarning("Missing input", "Please select a carrier WAV file.")
            return
        if not os.path.exists(wav_path):
            messagebox.showerror("File not found", "Carrier WAV path does not exist.")
            return
        if not password:
            messagebox.showwarning(
                "Missing password", "Please enter an encryption password."
            )
            return
        if not msg:
            messagebox.showwarning(
                "Missing message", "Please type a message or load a .txt file."
            )
            return
        if not out_name:
            messagebox.showwarning(
                "Missing output filename",
                "Please enter an output filename for the stego WAV.",
            )
            return

        # Ensure output ends with .wav
        if not out_name.lower().endswith(".wav"):
            out_name += ".wav"
        out_path = os.path.abspath(out_name)

        try:
            with wave.open(wav_path, "rb") as wf:
                sampwidth = wf.getsampwidth()
                if sampwidth != 2:
                    messagebox.showerror(
                        "Unsupported WAV",
                        "Only 16-bit PCM WAV files are supported. Convert your audio to 16-bit WAV.",
                    )
                    return

            # Build encrypted payload and embed
            self.set_status("Encrypting message and embedding into WAV...")
            message_bytes = msg.encode("utf-8")
            encrypt_message_and_embed(wav_path, message_bytes, password, out_path)
            self.set_status(f"Success: stego WAV saved to {out_path}")
            messagebox.showinfo(
                "Success", f"Message embedded successfully into:\n{out_path}"
            )
        except ValueError as ve:
            messagebox.showerror("Capacity/Error", f"{ve}")
            self.set_status("Error during embedding.")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error:\n{e}")
            self.set_status("Unexpected error.")

    def handle_decrypt(self):
        wav_path = self.dec_wav_var.get().strip()
        password = self.dec_pass_var.get()

        if not wav_path:
            messagebox.showwarning("Missing input", "Please select a stego WAV.")
            return
        if not os.path.exists(wav_path):
            messagebox.showerror("File not found", "Selected stego WAV does not exist.")
            return
        if not password:
            messagebox.showwarning(
                "Missing password", "Please enter the decryption password."
            )
            return

        try:
            self.set_status("Extracting payload and decrypting...")
            decrypted_bytes = extract_and_decrypt(wav_path, password)
            try:
                decoded = decrypted_bytes.decode("utf-8")
            except UnicodeDecodeError:
                decoded = repr(decrypted_bytes)
            self.dec_msg_display.delete("1.0", tk.END)
            self.dec_msg_display.insert(tk.END, decoded)
            self.set_status("Extraction & decryption successful.")
            messagebox.showinfo(
                "Success", "Message extracted and decrypted. See the box."
            )
        except ValueError as ve:
            messagebox.showerror("Decryption Error", f"{ve}")
            self.set_status("Decryption failed.")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error:\n{e}")
            self.set_status("Unexpected error.")


# Run app

if __name__ == "__main__":
    root = tk.Tk()
    app = AudioStegApp(root)
    root.mainloop()
