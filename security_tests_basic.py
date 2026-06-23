import os
import hmac
import json
import base64
import hashlib
import random
import sys
import importlib
from collections import Counter

# ============================================================
# CENTRAL TEST CONFIGURATION
# ============================================================
# To switch files, simply change this string to "main", "main_2", "main_3", etc.
TARGET_CIPHER_MODULE = "main_2"

GENESIS_SEED = "9dc598e1de13406673664556e228a7bd89ca341818d1773f7c9442e4ef4e0061"

# ============================================================
# DYNAMIC MODULE IMPORT
# ============================================================
try:
    cipher_module = importlib.import_module(TARGET_CIPHER_MODULE)
    mtc_encrypt = cipher_module.mtc_encrypt
    mtc_decrypt = cipher_module.mtc_decrypt
    derive_keys = cipher_module.derive_keys
    PureManifoldCipher = cipher_module.PureManifoldCipher
except ImportError:
    print(f"[-] CRITICAL ERROR: Could not find or load '{TARGET_CIPHER_MODULE}.py'.")
    print("    Ensure the file exists in the same folder and the name matches exactly.")
    sys.exit(1)


# ============================================================
# TEST UTILITIES
# ============================================================

def b64decode_padded(data: str) -> bytes:
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.b64decode(data)


def unpack_token(token: str) -> dict:
    return json.loads(b64decode_padded(token).decode("utf-8"))


def pack_token(package: dict) -> str:
    return base64.b64encode(json.dumps(package).encode("utf-8")).decode("utf-8")


def encrypt_with_forced_salt_iv(message: str, genesis_seed: str, salt: bytes, iv: bytes) -> str:
    plaintext = message.encode("utf-8")
    encryption_key, authentication_key = derive_keys(genesis_seed, salt)
    engine = PureManifoldCipher(encryption_key, iv)

    ciphertext = bytearray()

    for plain_byte in plaintext:
        keystream = engine.get_keystream_byte()
        cipher_byte = plain_byte ^ keystream
        ciphertext.append(cipher_byte)
        engine.mutate_manifold(cipher_byte)

    ciphertext = bytes(ciphertext)
    header = unpack_token(mtc_encrypt("", genesis_seed))["header"]
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")

    tag = hmac.new(
        authentication_key,
        header_bytes + salt + iv + ciphertext,
        hashlib.sha256
    ).digest()

    return pack_token({
        "header": header,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
    })


def bit_difference(a: bytes, b: bytes) -> int:
    max_len = max(len(a), len(b))
    a = a.ljust(max_len, b"\x00")
    b = b.ljust(max_len, b"\x00")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# ============================================================
# TEST EXECUTION MATRIX
# ============================================================

def test_round_trip():
    messages = ["hello", "The manifold lives.", "🚀 unicode test 🔥", "A" * 5000]

    for msg in messages:
        token = mtc_encrypt(msg, GENESIS_SEED)
        recovered = mtc_decrypt(token, GENESIS_SEED)
        assert recovered == msg

    print("[PASS] Round-trip encryption/decryption")


def test_wrong_seed_rejected():
    token = mtc_encrypt("attack at dawn", GENESIS_SEED)
    wrong_seed = "0" + GENESIS_SEED[1:] if GENESIS_SEED[0] != "0" else "1" + GENESIS_SEED[1:]

    try:
        mtc_decrypt(token, wrong_seed)
    except ValueError:
        pass
    else:
        raise AssertionError("Wrong seed was accepted")

    print("[PASS] Wrong Genesis Seed rejected")


def test_weak_seed_rejected():
    try:
        mtc_encrypt("weak seed test", "password")
    except ValueError:
        pass
    else:
        raise AssertionError("Weak Genesis Seed was accepted")

    print("[PASS] Weak Genesis Seed format rejected")


def test_tamper_rejected():
    token = mtc_encrypt("tamper test", GENESIS_SEED)
    original_package = unpack_token(token)

    for field in ["salt", "iv", "ciphertext", "tag"]:
        package = json.loads(json.dumps(original_package))
        raw = bytearray(b64decode_padded(package[field]))
        raw[0] ^= 1
        package[field] = base64.b64encode(bytes(raw)).decode("utf-8")

        tampered = base64.b64encode(json.dumps(package).encode("utf-8")).decode("utf-8")

        try:
            mtc_decrypt(tampered, GENESIS_SEED)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Tampered {field} was accepted")

    print("[PASS] Salt, IV, ciphertext, and tag tampering rejected")


def test_same_message_randomized():
    msg = "same message should not produce same ciphertext"
    tokens = [mtc_encrypt(msg, GENESIS_SEED) for _ in range(10)]
    assert len(set(tokens)) == len(tokens)
    print("[PASS] Same message produces different encrypted tokens")


def test_avalanche_plaintext_change():
    msg1 = "A" * 256
    msg2 = "B" + ("A" * 255)

    salt = b"P" * 16
    iv = b"Q" * 32

    token1 = encrypt_with_forced_salt_iv(msg1, GENESIS_SEED, salt, iv)
    token2 = encrypt_with_forced_salt_iv(msg2, GENESIS_SEED, salt, iv)

    c1 = b64decode_padded(unpack_token(token1)["ciphertext"])
    c2 = b64decode_padded(unpack_token(token2)["ciphertext"])

    diff = bit_difference(c1, c2)
    total_bits = max(len(c1), len(c2)) * 8
    rate = diff / total_bits

    print(f"[INFO] Avalanche rate: {rate:.2%}")
    assert rate > 0.30

    print("[PASS] Plaintext avalanche test")


def test_keystream_frequency():
    salt = b"0" * 16
    iv = b"1" * 32

    encryption_key, _ = derive_keys(GENESIS_SEED, salt)
    engine = PureManifoldCipher(encryption_key, iv)

    sample = bytearray()

    for _ in range(10_000):
        k = engine.get_keystream_byte()
        sample.append(k)
        engine.mutate_manifold(k)

    counts = Counter(sample)
    expected = len(sample) / 256

    chi_square = sum(
        ((counts.get(i, 0) - expected) ** 2) / expected
        for i in range(256)
    )

    print(f"[INFO] Keystream chi-square: {chi_square:.2f}")
    assert chi_square < 400

    print("[PASS] No obvious keystream byte-frequency bias")


def test_bit_flip_distribution():
    message = "B" * 512
    token = mtc_encrypt(message, GENESIS_SEED)
    package = unpack_token(token)

    ciphertext = bytearray(b64decode_padded(package["ciphertext"]))
    flip_index = random.randint(0, len(ciphertext) - 1)
    ciphertext[flip_index] ^= 1

    package["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("utf-8")
    tampered = base64.b64encode(json.dumps(package).encode("utf-8")).decode("utf-8")

    try:
        mtc_decrypt(tampered, GENESIS_SEED)
    except ValueError:
        pass
    else:
        raise AssertionError("Bit-flipped ciphertext decrypted successfully")

    print("[PASS] Random ciphertext bit flip rejected")


def run_all_tests():
    print("=" * 72)
    print("        BASIC PURE MANIFOLD CIPHER SECURITY TESTS")
    print(f"        TARGET MODULE UNDER TESTING: {TARGET_CIPHER_MODULE}.py")
    print("=" * 72)

    test_round_trip()
    test_weak_seed_rejected()
    test_wrong_seed_rejected()
    test_tamper_rejected()
    test_same_message_randomized()
    test_avalanche_plaintext_change()
    test_keystream_frequency()
    test_bit_flip_distribution()

    print("=" * 72)
    print(f"[SUCCESS] Basic security tests for {TARGET_CIPHER_MODULE.upper()} completed")
    print("=" * 72)


if __name__ == "__main__":
    run_all_tests()
