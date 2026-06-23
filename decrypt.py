import hmac
import json
import base64
import hashlib
import sys
import importlib

# ============================================================
# CENTRAL CONFIGURATION
# ============================================================
# Change this string to dynamically mirror your active build architecture!
TARGET_CIPHER_MODULE = "main_2"
GENESIS_SEED = "9dc598e1de13406673664556e228a7bd89ca341818d1773f7c9442e4ef4e0061"

# ============================================================
# DYNAMIC MODULE IMPORT
# ============================================================
try:
    cipher_module = importlib.import_module(TARGET_CIPHER_MODULE)
    derive_keys = cipher_module.derive_keys
    # Automatically tracks whichever variation of PureManifoldCipher/NonlinearManifoldCipher is exported
    PureManifoldCipher = getattr(cipher_module, "PureManifoldCipher", None) or getattr(cipher_module, "NonlinearManifoldCipher")
except ImportError:
    print(f"[-] CRITICAL ERROR: Could not find or load '{TARGET_CIPHER_MODULE}.py'.")
    sys.exit(1)


def b64decode_padded(data: str) -> bytes:
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.b64decode(data)


def mtc_decrypt(token: str, genesis_seed: str) -> str:
    if not genesis_seed:
        raise ValueError("Genesis Seed cannot be empty.")

    package = json.loads(b64decode_padded(token).decode("utf-8"))

    header = package["header"]
    salt = b64decode_padded(package["salt"])
    iv = b64decode_padded(package["iv"])
    ciphertext = b64decode_padded(package["ciphertext"])
    received_tag = b64decode_padded(package["tag"])

    encryption_key, authentication_key = derive_keys(genesis_seed, salt)
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")

    expected_tag = hmac.new(
        authentication_key,
        header_bytes + salt + iv + ciphertext,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(received_tag, expected_tag):
        raise ValueError("Authentication failed. Wrong Genesis Seed or tampered ciphertext.")

    # Spins up the dynamic module engine variant
    engine = PureManifoldCipher(encryption_key, iv)
    plaintext = bytearray()

    for cipher_byte in ciphertext:
        keystream = engine.get_keystream_byte()
        plain_byte = cipher_byte ^ keystream
        plaintext.append(plain_byte)
        engine.mutate_manifold(cipher_byte)

    return plaintext.decode("utf-8")


if __name__ == "__main__":
    print("=" * 72)
    print("        DYNAMIC MANIFOLD TRAJECTORY CIPHER DECRYPTOR")
    print(f"        LINKED ARCHITECTURE BUILD: {TARGET_CIPHER_MODULE.upper()}.py")
    print("=" * 72)

    seed_input = input(f"\n[>] Enter Genesis Seed [Default: {GENESIS_SEED[:8]}...]: ").strip()
    active_seed = seed_input if seed_input else GENESIS_SEED

    print("\n[>] Paste encrypted token below.")
    encrypted_token = input("[>] Token: ").strip()

    try:
        recovered_text = mtc_decrypt(encrypted_token, active_seed)
        print("-" * 72)
        print("[+] DECRYPTION SUCCESSFUL")
        print(f"[+] PLAINTEXT MESSAGE: \"{recovered_text}\"")
        print("-" * 72)
    except Exception as error:
        print("-" * 72)
        print("[!] DECRYPTION FAILED")
        print(f"[!] Reason: {error}")
        print("-" * 72)