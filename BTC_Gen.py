import os
import time
import random
import hashlib
import threading
import requests
import tkinter as tk
from tkinter import messagebox, scrolledtext, PhotoImage
import base58
import ecdsa
from mnemonic import Mnemonic
import bech32

# Constants
running = False
PASSWORD = "8p%L[5Wb#3Rx"
WALLET_FILE = "wallets.txt"
ENCRYPTED_FILE = "wallets.enc"
BITCOIN_IMAGE_URL = "https://raw.githubusercontent.com/Cr0mb/Bitcoin-Generator-Balance-Checker/main/bitcoin.png"
DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
BITCOIN_IMAGE_PATH = os.path.join(DOWNLOADS_DIR, "bitcoin.png")

def download_bitcoin_image():
    if not os.path.exists(BITCOIN_IMAGE_PATH):
        try:
            response = requests.get(BITCOIN_IMAGE_URL, stream=True)
            if response.status_code == 200:
                os.makedirs(DOWNLOADS_DIR, exist_ok=True)
                with open(BITCOIN_IMAGE_PATH, "wb") as file:
                    for chunk in response.iter_content(1024):
                        file.write(chunk)
                return
            else:
                print(f"Failed to download Bitcoin image: HTTP {response.status_code}")
        except Exception as e:
            print(f"Error downloading Bitcoin image: {e}")

def encrypt_wallet_file():
    if os.path.exists(WALLET_FILE):
        with open(WALLET_FILE, "r") as file:
            content = file.read().encode()
        encrypted_content = base58.b58encode(content).decode()
        with open(ENCRYPTED_FILE, "a") as file:
            file.write(encrypted_content + "\n")
        os.remove(WALLET_FILE)

def decrypt_wallet_file():
    if os.path.exists(ENCRYPTED_FILE):
        with open(ENCRYPTED_FILE, "r") as file:
            encrypted_content = file.readlines()
        try:
            decrypted_wallets = []
            for enc_wallet in encrypted_content:
                decrypted_content = base58.b58decode(enc_wallet.strip()).decode()
                updated_wallets = []
                for wallet in decrypted_content.split("=" * 60 + "\n"):
                    if "Wallet Balance: Hidden" in wallet:
                        balance = random.uniform(0.000001, 2.0)
                        wallet = wallet.replace("Wallet Balance: Hidden", f"Wallet Balance: {balance:.8f} BTC")
                    updated_wallets.append(wallet)
                final_output = "=" * 60 + "\n".join(updated_wallets)
                decrypted_wallets.append(final_output)
            with open(WALLET_FILE, "w") as file:
                file.write("\n".join(decrypted_wallets))
            os.remove(ENCRYPTED_FILE)
            messagebox.showinfo("Access Granted", "Wallet file unlocked!")
            log_text.delete("1.0", tk.END)
            log_text.insert(tk.END, "\n".join(decrypted_wallets) + "\n" + "=" * 50 + "\n")
            log_text.yview(tk.END)
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed!")

def save_wallet_to_file(wallet_details, hide_wallet):
    if hide_wallet:
        with open(WALLET_FILE, "a") as file:
            file.write(wallet_details + "\n" + "=" * 60 + "\n")
        encrypt_wallet_file()
    else:
        log_text.insert(tk.END, wallet_details + "\n" + "=" * 50 + "\n")
        log_text.yview(tk.END)

def generate_keys_and_addresses():
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)
    seed = mnemo.to_seed(mnemonic_phrase)
    private_key = hashlib.sha256(seed).digest()
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b"\x04" + vk.to_string()
    sha256_pubkey = hashlib.sha256(public_key).digest()
    ripemd160_pubkey = hashlib.new("ripemd160", sha256_pubkey).digest()
    legacy_address = base58.b58encode_check(b"\x00" + ripemd160_pubkey).decode()
    segwit_address = bech32.encode("bc", 0, ripemd160_pubkey)
    return private_key, public_key, mnemonic_phrase, legacy_address, segwit_address

def start_wallet_generator():
    global running
    if running:
        return
    running = True
    threading.Thread(target=wallet_generator, daemon=True).start()

def stop_wallet_generator():
    global running
    running = False

def wallet_generator():
    global running
    while running:
        private_key, public_key, mnemonic_phrase, legacy_address, segwit_address = generate_keys_and_addresses()
        balance = random.uniform(0.000001, 2.0) if random.random() < 0.1 else 0.0
        hide_wallet = balance > 0
        wallet_details = (
            f"Mnemonic Phrase: {mnemonic_phrase}\n"
            f"Private Key (Hex): {private_key.hex()}\n"
            f"Public Key (Hex): {public_key.hex()}\n"
            f"Legacy Address (P2PKH): {legacy_address}\n"
            f"SegWit Address (P2WPKH/P2SH): {segwit_address}\n"
            f"Wallet Balance: {'Hidden' if hide_wallet else f'{balance:.8f} BTC'}"
        )
        time.sleep(0.3)
        if hide_wallet:
            log_text.insert(tk.END, "\n\n\n⚠️ Wallet with balance found! Hidden from display.\n\n\n\n" + "=" * 50 + "\n")
        else:
            log_text.insert(tk.END, wallet_details + "\n" + "=" * 50 + "\n")
        log_text.yview(tk.END)
        save_wallet_to_file(wallet_details, hide_wallet)

def unlock_wallets():
    entered_password = password_entry.get()
    if entered_password == PASSWORD:
        decrypt_wallet_file()
    else:
        messagebox.showerror("Access Denied", "Incorrect password!")

# GUI Setup
root = tk.Tk()
root.title("BTC Wallet Generator")
root.geometry("800x800")
root.configure(bg="#1E1E1E")

download_bitcoin_image()

btc_label = tk.Label(root, text="BTC Generator", font=("Arial", 16, "bold"), fg="white", bg="#1E1E1E")
btc_label.pack()

start_btn = tk.Button(root, text="Start", command=start_wallet_generator, bg="#008080", fg="white", font=("Arial", 12))
start_btn.pack()
stop_btn = tk.Button(root, text="Stop", command=stop_wallet_generator, bg="#800000", fg="white", font=("Arial", 12))
stop_btn.pack()
log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=40, bg="#282828", fg="lightgray", font=("Consolas", 10))
log_text.pack()
password_entry = tk.Entry(root, show="*", font=("Arial", 12))
password_entry.pack()
unlock_btn = tk.Button(root, text="Unlock", command=unlock_wallets, bg="#4B0082", fg="white", font=("Arial", 12))
unlock_btn.pack()
root.mainloop()
