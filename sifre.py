import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import getpass
import tkinter as tk
from tkinter import filedialog

SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100_000
BLOCK_SIZE = AES.block_size

def pad(data):
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    if padding_len > BLOCK_SIZE:
        raise ValueError("Padding yanlış.")
    return data[:-padding_len]

def derive_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt_file(filepath, password):
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        salt = get_random_bytes(SALT_SIZE)
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data))

        with open(filepath + ".enc", "wb") as f:
            f.write(salt + cipher.iv + ct_bytes)

        os.remove(filepath)
        print(f"Şifrelendi: {filepath}")
    except Exception as e:
        print(f"Hata şifrelerken {filepath}: {e}")

def decrypt_file(filepath, password):
    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        salt = raw[:SALT_SIZE]
        iv = raw[SALT_SIZE:SALT_SIZE+BLOCK_SIZE]
        ct = raw[SALT_SIZE+BLOCK_SIZE:]

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct))

        orig_filepath = filepath[:-4]

        with open(orig_filepath, "wb") as f:
            f.write(pt)

        os.remove(filepath)
        print(f"Şifre çözüldü: {orig_filepath}")
    except Exception as e:
        print(f"Hata çözerken {filepath}: {e}")

def encrypt_folder(folder_path, password):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".enc"):
                continue
            full_path = os.path.join(root, file)
            encrypt_file(full_path, password)

def decrypt_folder(folder_path, password):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".enc"):
                full_path = os.path.join(root, file)
                decrypt_file(full_path, password)

def select_folder():
    root = tk.Tk()
    root.withdraw()
    folder_selected = filedialog.askdirectory()
    return folder_selected

def main():
    while True:
        print("\n--- Dosya Şifreleme Uygulaması ---")
        print("1) Şifrele")
        print("2) Şifre Çöz")
        print("3) Çıkış")
        choice = input("Seçiminiz: ").strip()

        if choice == "1":
            print("Lütfen şifrelemek istediğiniz klasörü seçin.")
            folder = select_folder()
            if not folder:
                print("Klasör seçilmedi, ana menüye dönülüyor.")
                continue
            password = getpass.getpass("Şifreyi girin: ")
            encrypt_folder(folder, password)
            print("Şifreleme tamamlandı.")

        elif choice == "2":
            print("Lütfen şifre çözmek istediğiniz klasörü seçin.")
            folder = select_folder()
            if not folder:
                print("Klasör seçilmedi, ana menüye dönülüyor.")
                continue
            password = getpass.getpass("Şifreyi girin: ")
            decrypt_folder(folder, password)
            print("Şifre çözme tamamlandı.")

        elif choice == "3":
            print("Programdan çıkılıyor. Görüşürüz kanka!")
            break
        else:
            print("Geçersiz seçim, tekrar deneyin.")

if __name__ == "__main__":
    main()
