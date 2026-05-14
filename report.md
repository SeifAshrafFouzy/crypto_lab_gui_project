# Cryptography Lib Lab — Project Report

**Student:** [Your Name]  
**Course:** Cryptography / Information Security Lab  
**Date:** 2025  

---

## 1. Scenario

**Secure Student Records** — A CSV file containing fake student names, IDs, emails,
grades, and GPAs is encrypted to simulate protecting sensitive academic records.  
The project implements all three allowed paths (AES only, AES vs DES comparison,
and hybrid AES+RSA encryption).

---

## 2. Algorithms Used

| Algorithm    | Mode    | Key Size | Block/IV Size | Role                       |
|-------------|---------|----------|---------------|----------------------------|
| AES-256     | CBC     | 256-bit  | 128-bit / 16B | Main data encryption        |
| DES         | CBC     | 64-bit*  | 64-bit / 8B   | Educational comparison only |
| RSA         | OAEP    | 2048-bit | —             | Wraps the AES session key   |

*56 bits effective (8 bits are parity). DES is cryptographically broken.

---

## 3. Key Details

**AES key** — 32 random bytes generated with `os.urandom(32)` each run.  
Stored in `aes_metadata.json` (in a real system this would be in a key vault).

**DES key** — 8 random bytes (`os.urandom(8)`), used only for the comparison demo.

**RSA keys** — 2048-bit pair generated with `rsa.generate_private_key()`.
Public key encrypts the AES key; private key decrypts it.

---

## 4. Role of IV / Nonce

AES-CBC and DES-CBC both require an **Initialisation Vector (IV)**.  
The IV is:
- Generated randomly each run with `os.urandom(16)` (AES) or `os.urandom(8)` (DES).
- **Not secret** — stored alongside the ciphertext in `*_metadata.json`.
- Its purpose is to ensure that encrypting the same plaintext twice produces
  different ciphertexts, preventing pattern analysis.

---

## 5. What the Encrypted Output Looks Like

The original CSV is human-readable UTF-8 text:

```
StudentID,Name,Email,Grade,GPA,Major
STU001,Alice Johnson,alice.johnson@university.edu,Senior,3.85,Computer Science
```

After AES-256-CBC encryption the output is random binary bytes, displayed in
Base64 as:

```
qnqrl2qipsABxMtTRXWAzHI7XrWXucZr3ia/tIDBQIqc/Pk0eKyPo9vaiQDeDUgj...
```

There is no recognisable structure; the original data is completely hidden.

---

## 6. Verification Method

After decryption, the program computes the **SHA-256 hash** of both the
original file bytes and the decrypted file bytes.  
If they are identical, it prints:

```
[✓] VERIFICATION : SUCCESS — decrypted file matches original (SHA-256).
    Original SHA-256  : 06f19e88…
    Decrypted SHA-256 : 06f19e88…
```

This provides cryptographic proof that not a single byte was altered.

---

## 7. AES vs DES Comparison Results (sample run)

| Metric               | AES-256-CBC | DES-CBC          |
|---------------------|-------------|-----------------|
| Key size             | 256 bits    | 64-bit (56 eff) |
| Block size           | 128 bits    | 64 bits         |
| Ciphertext size      | 816 bytes   | 808 bytes       |
| Encrypt time         | ~1.1 ms     | ~0.07 ms        |
| Decrypt time         | ~0.04 ms    | ~0.04 ms        |
| Verification         | ✓ PASS      | ✓ PASS          |

DES is slightly faster on this tiny file because its key schedule is simpler,
but its 56-bit key was brute-forced publicly in 1998 (DES Cracker, EFF).
AES-256 provides 2^256 key space — computationally infeasible to break.

---

## 8. Security Limitation

The biggest limitation of this project is **key management**.  
The AES key is stored in a plaintext JSON file on disk (`aes_metadata.json`).
In a real application, keys must be stored in a hardware security module (HSM)
or a dedicated key-management service (e.g., AWS KMS, HashiCorp Vault).

The hybrid mode (Mode 3) partially addresses this: the AES key is RSA-wrapped,
so anyone without the RSA private key cannot recover it.  
However, the RSA private key itself is held only in memory during the demo run.

---

## 9. Library Used

**`cryptography`** (PyCA) — `pip install cryptography`  
Selected because it is actively maintained, covers AES/DES/RSA, enforces safe
defaults (e.g., OAEP padding for RSA, PKCS7 for block ciphers), and is the
recommended library in Anthropic/Python community best-practice guides.

---

## 10. Program Flow Diagram

```
Load students.csv
      │
      ▼
Generate AES-256 key ──────────────────────┐
      │                                    │ (Mode 3 only)
      ▼                                    ▼
AES-256-CBC Encrypt              RSA-2048 wrap AES key
      │                                    │
      ▼                                    ▼
Save ciphertext (.bin)          Save wrapped_key.bin
Save IV + metadata (.json)
      │
      ▼
AES-256-CBC Decrypt
      │
      ▼
SHA-256 hash comparison
      │
      ▼
VERIFICATION : SUCCESS ✓
```
