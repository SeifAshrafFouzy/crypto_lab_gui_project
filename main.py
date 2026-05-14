"""
main.py
-------
Cryptography Lib Lab — Main Program
Supports three modes via CLI menu:
  1. AES-256 file encryption / decryption
  2. AES vs DES comparison on the same file
  3. Hybrid encryption (AES data + RSA key wrapping)
"""

import os
import sys
import base64

import crypto_utils as cu

DATA_DIR   = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

SEP = "─" * 60


def banner():
    print(f"""
╔══════════════════════════════════════════════════════════╗
║          C R Y P T O G R A P H Y   L I B   L A B        ║
║   AES-256 · DES · RSA  |  Educational Crypto Project     ║
╚══════════════════════════════════════════════════════════╝
""")


def menu():
    print("Select a mode:")
    print("  [1] AES-256 File Encryption & Decryption")
    print("  [2] AES vs DES Algorithm Comparison")
    print("  [3] Hybrid Encryption  (AES data + RSA key wrap)")
    print("  [q] Quit")
    return input("\nChoice › ").strip().lower()


# ──────────────────────────────────────────────────────────
#  MODE 1 — AES-256 Encrypt / Decrypt
# ──────────────────────────────────────────────────────────

def mode_aes(input_path: str):
    print(f"\n{SEP}")
    print(" MODE 1 · AES-256-CBC File Encryption")
    print(SEP)

    plaintext = cu.load_file(input_path)
    print(f"[✓] Original file loaded : {os.path.basename(input_path)}  ({len(plaintext)} bytes)")
    print(f"    SHA-256 : {cu.sha256_hash(plaintext)}")

    # Key generation
    aes_key = cu.generate_aes_key(256)
    print(f"[✓] AES-256 key generated : {aes_key.hex()[:32]}…  (256-bit)")

    # Encrypt
    enc_result, enc_time = cu.timed_aes_encrypt(plaintext, aes_key)
    enc_path  = os.path.join(OUTPUT_DIR, "aes_encrypted.bin")
    meta_path = os.path.join(OUTPUT_DIR, "aes_metadata.json")

    cu.save_file(enc_path, enc_result["ciphertext"])
    cu.save_metadata(meta_path, {
        "algorithm" : "AES-256-CBC",
        "key"       : aes_key,
        "iv"        : enc_result["iv"],
        "original_size": len(plaintext),
    })

    b64_preview = base64.b64encode(enc_result["ciphertext"][:48]).decode()
    print(f"[✓] Encrypted → {os.path.basename(enc_path)}  ({len(enc_result['ciphertext'])} bytes)  [{enc_time*1000:.3f} ms]")
    print(f"    Base64 preview : {b64_preview}…")

    # Decrypt
    dec_result, dec_time = cu.timed_aes_decrypt(enc_result["ciphertext"], aes_key, enc_result["iv"])
    dec_path = os.path.join(OUTPUT_DIR, "aes_decrypted.csv")
    cu.save_file(dec_path, dec_result)
    print(f"[✓] Decrypted  → {os.path.basename(dec_path)}  ({len(dec_result)} bytes)  [{dec_time*1000:.3f} ms]")

    # Verify
    ok = cu.verify_files(plaintext, dec_result)
    print(f"\n{'[✓] VERIFICATION : SUCCESS — decrypted file matches original (SHA-256).' if ok else '[✗] VERIFICATION : FAILED — files do NOT match!'}")
    print(f"    Original SHA-256  : {cu.sha256_hash(plaintext)}")
    print(f"    Decrypted SHA-256 : {cu.sha256_hash(dec_result)}")


# ──────────────────────────────────────────────────────────
#  MODE 2 — AES vs DES Comparison
# ──────────────────────────────────────────────────────────

def mode_compare(input_path: str):
    print(f"\n{SEP}")
    print(" MODE 2 · AES-256 vs DES Algorithm Comparison")
    print(SEP)

    plaintext = cu.load_file(input_path)
    print(f"[✓] Input file : {os.path.basename(input_path)}  ({len(plaintext)} bytes)")
    print(f"    SHA-256    : {cu.sha256_hash(plaintext)}\n")

    aes_key = cu.generate_aes_key(256)
    des_key = cu.generate_des_key()

    # ── AES ──
    aes_enc, aes_enc_t = cu.timed_aes_encrypt(plaintext, aes_key)
    aes_dec, aes_dec_t = cu.timed_aes_decrypt(aes_enc["ciphertext"], aes_key, aes_enc["iv"])
    aes_ok = cu.verify_files(plaintext, aes_dec)

    aes_enc_path = os.path.join(OUTPUT_DIR, "compare_aes.bin")
    aes_dec_path = os.path.join(OUTPUT_DIR, "compare_aes_dec.csv")
    cu.save_file(aes_enc_path, aes_enc["ciphertext"])
    cu.save_file(aes_dec_path, aes_dec)

    # ── DES ──
    des_enc, des_enc_t = cu.timed_des_encrypt(plaintext, des_key)
    des_dec, des_dec_t = cu.timed_des_decrypt(des_enc["ciphertext"], des_key, des_enc["iv"])
    des_ok = cu.verify_files(plaintext, des_dec)

    des_enc_path = os.path.join(OUTPUT_DIR, "compare_des.bin")
    des_dec_path = os.path.join(OUTPUT_DIR, "compare_des_dec.csv")
    cu.save_file(des_enc_path, des_enc["ciphertext"])
    cu.save_file(des_dec_path, des_dec)

    # ── Report ──
    col = 28
    print(f"{'Metric':<{col}} {'AES-256-CBC':>16} {'DES-CBC':>16}")
    print("─" * (col + 34))
    print(f"{'Key size (bits)':<{col}} {'256':>16} {'64 (56 effective)':>16}")
    print(f"{'Block size (bits)':<{col}} {'128':>16} {'64':>16}")
    print(f"{'IV size (bytes)':<{col}} {'16':>16} {'8':>16}")
    print(f"{'Plaintext size (bytes)':<{col}} {len(plaintext):>16} {len(plaintext):>16}")
    print(f"{'Ciphertext size (bytes)':<{col}} {len(aes_enc['ciphertext']):>16} {len(des_enc['ciphertext']):>16}")
    print(f"{'Encrypt time (ms)':<{col}} {aes_enc_t*1000:>16.4f} {des_enc_t*1000:>16.4f}")
    print(f"{'Decrypt time (ms)':<{col}} {aes_dec_t*1000:>16.4f} {des_dec_t*1000:>16.4f}")
    print(f"{'Decryption verified':<{col}} {'✓ PASS' if aes_ok else '✗ FAIL':>16} {'✓ PASS' if des_ok else '✗ FAIL':>16}")
    print()
    print("⚠  Security note: DES is cryptographically broken (56-bit key,")
    print("   exhaustive search feasible). Use AES-256 for real applications.")


# ──────────────────────────────────────────────────────────
#  MODE 3 — Hybrid Encryption (AES + RSA)
# ──────────────────────────────────────────────────────────

def mode_hybrid(input_path: str):
    print(f"\n{SEP}")
    print(" MODE 3 · Hybrid Encryption (AES-256 data + RSA-2048 key wrap)")
    print(SEP)

    plaintext = cu.load_file(input_path)
    print(f"[✓] Original file : {os.path.basename(input_path)}  ({len(plaintext)} bytes)")
    print(f"    SHA-256       : {cu.sha256_hash(plaintext)}\n")

    # Generate keys
    rsa_priv, rsa_pub = cu.generate_rsa_keypair(2048)
    aes_key = cu.generate_aes_key(256)
    print("[✓] RSA-2048 key pair generated.")
    print(f"[✓] AES-256 session key : {aes_key.hex()[:32]}…")

    # Encrypt data with AES
    enc_result, enc_time = cu.timed_aes_encrypt(plaintext, aes_key)
    enc_path = os.path.join(OUTPUT_DIR, "hybrid_encrypted.bin")
    cu.save_file(enc_path, enc_result["ciphertext"])
    print(f"[✓] Data encrypted with AES-256  → {os.path.basename(enc_path)}  [{enc_time*1000:.3f} ms]")

    # Encrypt AES key with RSA
    wrapped_key = cu.rsa_encrypt_key(aes_key, rsa_pub)
    wrapped_path = os.path.join(OUTPUT_DIR, "hybrid_wrapped_key.bin")
    cu.save_file(wrapped_path, wrapped_key)
    print(f"[✓] AES key wrapped with RSA-2048 → {os.path.basename(wrapped_path)}  ({len(wrapped_key)} bytes)")

    # Save IV
    meta_path = os.path.join(OUTPUT_DIR, "hybrid_metadata.json")
    cu.save_metadata(meta_path, {"iv": enc_result["iv"], "algorithm": "AES-256-CBC + RSA-2048-OAEP"})

    # ── Decryption side ──
    print(f"\n[…] Decrypting: unwrap AES key via RSA private key…")
    recovered_key = cu.rsa_decrypt_key(wrapped_key, rsa_priv)
    assert recovered_key == aes_key, "RSA key unwrap mismatch!"
    print(f"[✓] AES session key recovered successfully.")

    dec_result, dec_time = cu.timed_aes_decrypt(enc_result["ciphertext"], recovered_key, enc_result["iv"])
    dec_path = os.path.join(OUTPUT_DIR, "hybrid_decrypted.csv")
    cu.save_file(dec_path, dec_result)
    print(f"[✓] Data decrypted with recovered AES key → {os.path.basename(dec_path)}  [{dec_time*1000:.3f} ms]")

    ok = cu.verify_files(plaintext, dec_result)
    print(f"\n{'[✓] VERIFICATION : SUCCESS — hybrid decryption matches original (SHA-256).' if ok else '[✗] VERIFICATION : FAILED!'}")
    print(f"    Original SHA-256  : {cu.sha256_hash(plaintext)}")
    print(f"    Decrypted SHA-256 : {cu.sha256_hash(dec_result)}")


# ──────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────

def main():
    banner()

    # Resolve input file
    default_input = os.path.join(DATA_DIR, "students.csv")
    print(f"Default input file : {default_input}")
    custom = input("Press Enter to use default, or type a path › ").strip()
    input_path = custom if custom else default_input

    if not os.path.isfile(input_path):
        print(f"[✗] File not found: {input_path}")
        sys.exit(1)

    while True:
        choice = menu()
        if choice == "1":
            mode_aes(input_path)
        elif choice == "2":
            mode_compare(input_path)
        elif choice == "3":
            mode_hybrid(input_path)
        elif choice in ("q", "quit", "exit"):
            print("\nBye!")
            break
        else:
            print("Invalid choice, try again.")
        print()


if __name__ == "__main__":
    main()
