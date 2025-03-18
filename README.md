# BTC-Wallet-Generator
BTC Wallet Generator is a Python application that generates Bitcoin wallets, including mnemonic phrases, private keys, public keys, and addresses. It includes encryption and decryption mechanisms to secure wallet data, as well as a graphical user interface (GUI) for ease of use.

## Features
- Generates Bitcoin wallet addresses with mnemonic phrases.
- Encrypts and decrypts wallet data.
- Hides wallets with nonzero balances for added security.
- Saves wallets to a file and encrypts them automatically.
- Displays wallets with a zero balance in the GUI.
- Downloads and displays a Bitcoin logo.
- Allows unlocking encrypted wallet files with a password.

![image](https://github.com/user-attachments/assets/dbe72254-fe21-4fa6-9b61-7a154ae5d2c0)


## Requirements
```
pip install requests mnemonic ecdsa base58 bech32 tk
```

## Usage
1. Launch the application.
2. Click Start to begin generating wallets.
3. Wallets with a balance will be hidden and encrypted automatically.
4. Click Stop to stop the wallet generation process.
5. Use the Unlock button to decrypt saved wallet data by entering the correct password.

## Security Measures

Wallet balances are hidden when they contain funds.

Wallet data is encrypted using Base58 encoding.

Encrypted wallets require a password to be decrypted.
