import os
import hashlib
import base64
import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# --------------------------
# Automatic Folder Setup
# --------------------------
BASE_FOLDER = "FileEncryptorPro"
LOG_FOLDER = os.path.join(BASE_FOLDER, "logs")
BACKUP_FOLDER = os.path.join(BASE_FOLDER, "backup")
ENCRYPTED_FOLDER = os.path.join(BASE_FOLDER, "encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_FOLDER, "decrypted")

# Make folders if not exist
for folder in [BASE_FOLDER, LOG_FOLDER, BACKUP_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Log file path
LOG_FILE = os.path.join(LOG_FOLDER, "encryption_logs.txt")

# --------------------------
# Utilities
# --------------------------
def clear(): os.system("cls" if os.name=="nt" else "clear")
def pause(): input("\nPress Enter to continue...")
def current_time(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_action(action, filepath, status):
    with open(LOG_FILE,"a") as f:
        f.write(f"[{current_time()}] {action} File: {filepath} Status: {status}\n")

# --------------------------
# Password Strength Checker
# --------------------------
def check_password_strength(password):
    score = 0
    remarks = []
    if len(password)>=8: score+=20
    else: remarks.append("Password too short")
    if any(c.isupper() for c in password): score+=20
    else: remarks.append("Add uppercase letters")
    if any(c.islower() for c in password): score+=20
    else: remarks.append("Add lowercase letters")
    if any(c.isdigit() for c in password): score+=20
    else: remarks.append("Add numbers")
    if any(c in "@#$%^&*!" for c in password): score+=20
    else: remarks.append("Add special characters")
    return score, remarks

# --------------------------
# AES Encryption/Decryption
# --------------------------
def derive_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

def pad(data): pad_len = 16 - (len(data)%16); return data + bytes([pad_len]*pad_len)
def unpad(data): return data[:-data[-1]]

def encrypt_file(filepath, password):
    try:
        with open(filepath,"rb") as f: plaintext=f.read()
        salt=get_random_bytes(16)
        key=derive_key(password,salt)
        iv=get_random_bytes(16)
        cipher=AES.new(key,AES.MODE_CBC,iv)
        ciphertext=cipher.encrypt(pad(plaintext))

        # Backup original
        backup_path=os.path.join(BACKUP_FOLDER,os.path.basename(filepath))
        with open(backup_path,"wb") as bf: bf.write(plaintext)

        # Save encrypted file
        enc_file=os.path.join(ENCRYPTED_FOLDER,os.path.basename(filepath)+".enc")
        with open(enc_file,"wb") as ef: ef.write(salt+iv+ciphertext)

        log_action("ENCRYPT", filepath, "SUCCESS")
        print(Fore.GREEN+f"✅ File encrypted: {enc_file}")
        print(Fore.YELLOW+f"Backup saved: {backup_path}")

    except Exception as e:
        log_action("ENCRYPT", filepath, f"FAILED:{e}")
        print(Fore.RED+"❌ Encryption failed:", e)

def decrypt_file(filepath,password):
    try:
        with open(filepath,"rb") as f: raw=f.read()
        salt=raw[:16]; iv=raw[16:32]; ciphertext=raw[32:]
        key=derive_key(password,salt)
        cipher=AES.new(key,AES.MODE_CBC,iv)
        plaintext=unpad(cipher.decrypt(ciphertext))

        # Save decrypted file
        dec_file=os.path.join(DECRYPTED_FOLDER,os.path.basename(filepath).replace(".enc",".dec"))
        with open(dec_file,"wb") as f: f.write(plaintext)

        log_action("DECRYPT", filepath, "SUCCESS")
        print(Fore.GREEN+f"✅ File decrypted: {dec_file}")

    except Exception as e:
        log_action("DECRYPT", filepath, f"FAILED:{e}")
        print(Fore.RED+"❌ Decryption failed:", e)

# --------------------------
# Batch Functions
# --------------------------
def batch_encrypt(files,password):
    for f in files: encrypt_file(f,password)
def batch_decrypt(files,password):
    for f in files: decrypt_file(f,password)

# --------------------------
# CLI Menu
# --------------------------
def menu():
    while True:
        clear()
        print(Fore.CYAN+"===================================")
        print(Fore.CYAN+" 🔐 Professional File Encryptor CLI ")
        print(Fore.CYAN+"===================================\n")
        print(Fore.YELLOW+"1. Encrypt a File")
        print("2. Decrypt a File")
        print("3. Batch Encrypt Files")
        print("4. Batch Decrypt Files")
        print("5. Check Password Strength")
        print("6. View Logs")
        print("7. Exit")
        choice=input("\nEnter choice: ").strip()
        if choice=="1":
            fp=input("Enter file path: ").strip()
            if not os.path.isfile(fp): print(Fore.RED+"❌ File not found"); pause(); continue
            pw=getpass("Enter encryption password: ")
            batch_encrypt([fp],pw); pause()
        elif choice=="2":
            fp=input("Enter file path: ").strip()
            if not os.path.isfile(fp): print(Fore.RED+"❌ File not found"); pause(); continue
            pw=getpass("Enter decryption password: ")
            batch_decrypt([fp],pw); pause()
        elif choice=="3":
            fps=input("Enter file paths (comma separated): ").split(",")
            fps=[f.strip() for f in fps if os.path.isfile(f.strip())]
            if not fps: print(Fore.RED+"❌ No valid files"); pause(); continue
            pw=getpass("Enter encryption password: ")
            batch_encrypt(fps,pw); pause()
        elif choice=="4":
            fps=input("Enter file paths (comma separated): ").split(",")
            fps=[f.strip() for f in fps if os.path.isfile(f.strip())]
            if not fps: print(Fore.RED+"❌ No valid files"); pause(); continue
            pw=getpass("Enter decryption password: ")
            batch_decrypt(fps,pw); pause()
        elif choice=="5":
            pw=getpass("Enter password to check strength: ")
            score, remarks=check_password_strength(pw)
            print(Fore.YELLOW+f"\nStrength Score: {score}%")
            if score==100: print(Fore.GREEN+"✅ Strong Password")
            else: print(Fore.RED+"⚠️ Weak Password Suggestions:"); [print(" -",r) for r in remarks]
            pause()
        elif choice=="6":
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE,"r") as f: print("\n"+f.read())
            else: print("No logs yet.")
            pause()
        elif choice=="7":
            print(Fore.CYAN+"Exiting... Stay Secure! 🔐"); break
        else: print(Fore.RED+"❌ Invalid choice!"); pause()

# --------------------------
# Run
# --------------------------
if __name__=="__main__":
    try: menu()
    except KeyboardInterrupt: print("\nExiting... Bye!")
