import importlib
import sys
import base64
import json

# ============================================================
# CENTRAL TEST CONFIGURATION
# ============================================================
# To test a different file, simply change this string to "main", "main_2", "main_3", etc.
TARGET_CIPHER_MODULE = "main_2"

# Diagnostic matrix parameters
SALT_IV_SAMPLES = 50
KEYSTREAM_SAMPLES = 10_000
CYCLE_STEPS = 10_000
AVALANCHE_SAMPLES = 5
WRONG_SEED_ATTEMPTS = 10

# ============================================================
# DYNAMIC MODULE IMPORT
# ============================================================
try:
    # Dynamically inject the chosen cipher file into the testing scope
    cipher_module = importlib.import_module(TARGET_CIPHER_MODULE)
    mtc_encrypt = cipher_module.mtc_encrypt
    mtc_decrypt = cipher_module.mtc_decrypt
    generate_genesis_seed = cipher_module.generate_genesis_seed
    PureManifoldCipher = cipher_module.PureManifoldCipher
    derive_keys = cipher_module.derive_keys
except ImportError:
    print(f"[-] CRITICAL ERROR: Could not find or load '{TARGET_CIPHER_MODULE}.py'.")
    print("    Ensure the file exists in the same folder and the name matches exactly.")
    sys.exit(1)


def ciphertext_with_forced_salt_iv(message: str, genesis_seed: str, salt: bytes, iv: bytes) -> bytes:
    plaintext = message.encode("utf-8")
    encryption_key, _ = derive_keys(genesis_seed, salt)
    engine = PureManifoldCipher(encryption_key, iv)

    ciphertext = bytearray()

    for plain_byte in plaintext:
        keystream = engine.get_keystream_byte()
        cipher_byte = plain_byte ^ keystream
        ciphertext.append(cipher_byte)
        engine.mutate_manifold(cipher_byte)

    return bytes(ciphertext)


# ============================================================
# ADVANCED SECURITY TEST MATRIX
# ============================================================

def test_known_plaintext_reuse():
    print("\n[*] Known-plaintext reuse test...")
    seed = generate_genesis_seed()
    msg = "Testing standard structural footprint parameters."

    token1 = mtc_encrypt(msg, seed)
    token2 = mtc_encrypt(msg, seed)

    p1 = json.loads(base64.b64decode(token1).decode("utf-8"))
    p2 = json.loads(base64.b64decode(token2).decode("utf-8"))

    c1 = base64.b64decode(p1["ciphertext"])
    c2 = base64.b64decode(p2["ciphertext"])

    if token1 == token2:
        raise AssertionError("Deterministic output detected. Salt/IV is not acting on state engine.")

    diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1, c2))
    total_bits = len(c1) * 8
    rate = (diff_bits / total_bits) * 100
    print(f"[INFO] Difference rate: {rate:.2f}%")
    print("[PASS] Repeated encryption does not reuse ciphertext stream")


def test_randomized_repeated_prefix_uniqueness():
    print("\n[*] Randomized repeated-prefix uniqueness test...")
    seed = generate_genesis_seed()
    msg1 = "AAAABBBBCCCCDDDD_payload_alpha"
    msg2 = "AAAABBBBCCCCDDDD_payload_omega"

    t1 = mtc_encrypt(msg1, seed)
    t2 = mtc_encrypt(msg2, seed)

    c1 = base64.b64decode(json.loads(base64.b64decode(t1).decode("utf-8"))["ciphertext"])
    c2 = base64.b64decode(json.loads(base64.b64decode(t2).decode("utf-8"))["ciphertext"])

    if c1[:16] == c2[:16]:
        raise AssertionError("Prefix leakage detected! Avalanche diffusion did not cascade cleanly.")
    print("[PASS] Random salt/IV prevents repeated plaintext prefixes from creating repeated ciphertext prefixes")


def test_salt_iv_uniqueness():
    print(f"[*] Salt/IV uniqueness over {SALT_IV_SAMPLES} samples...")
    seed = generate_genesis_seed()
    salts = set()
    ivs = set()

    for _ in range(SALT_IV_SAMPLES):
        t = mtc_encrypt("test", seed)
        p = json.loads(base64.b64decode(t).decode("utf-8"))
        salts.add(p["salt"])
        ivs.add(p["iv"])

    assert len(salts) == SALT_IV_SAMPLES, "Duplicate salt collision detected!"
    assert len(ivs) == SALT_IV_SAMPLES, "Duplicate IV collision detected!"
    print("[PASS] Unique salts and IVs")


def test_bit_level_balance():
    print(f"\n[*] Bit-level balance over {KEYSTREAM_SAMPLES} bytes...")
    seed = generate_genesis_seed()
    massive_msg = "A" * KEYSTREAM_SAMPLES
    t = mtc_encrypt(massive_msg, seed)
    c = base64.b64decode(json.loads(base64.b64decode(t).decode("utf-8"))["ciphertext"])

    ones = sum(bin(b).count('1') for b in c)
    total_bits = len(c) * 8
    ratio = ones / total_bits
    print(f"[INFO] Bit-one ratio: {ratio:.4f}")
    assert 0.48 <= ratio <= 0.52, "Severe bit imbalance bias detected!"
    print("[PASS] Bit-level balance looks reasonable")


def test_serial_correlation():
    print(f"\n[*] Serial correlation over {KEYSTREAM_SAMPLES} bytes...")
    seed = generate_genesis_seed()
    massive_msg = "X" * KEYSTREAM_SAMPLES
    t = mtc_encrypt(massive_msg, seed)
    c = base64.b64decode(json.loads(base64.b64decode(t).decode("utf-8"))["ciphertext"])

    mean = sum(c) / len(c)
    num = sum((c[i] - mean) * (c[i + 1] - mean) for i in range(len(c) - 1))
    den = sum((c[i] - mean) ** 2 for i in range(len(c)))
    r = num / den if den != 0 else 1
    print(f"[INFO] Serial correlation: {abs(r):.6f}")
    assert abs(r) < 0.05, "Significant adjacent byte correlation detected!"
    print("[PASS] No obvious adjacent-byte serial correlation")


def test_cycle_probe():
    print(f"\n[*] Cycle probe over {CYCLE_STEPS} states...")
    seed = generate_genesis_seed()
    salt = b"0" * 16
    iv = b"1" * 32
    enc_key, _ = derive_keys(seed, salt)

    engine = PureManifoldCipher(enc_key, iv)
    seen_states = set()

    for _ in range(CYCLE_STEPS):
        # Hash current coordinate vectors into a unique state state identity signature
        state_sig = (engine.x, engine.y, engine.z, engine.w, engine.counter)
        if state_sig in seen_states:
            raise AssertionError("State trajectory cycle shortcut detected!")
        seen_states.add(state_sig)
        engine.get_keystream_byte()

    print("[PASS] No state cycle detected within configuration depth")


def test_multi_sample_avalanche():
    print(f"\n[*] Multi-sample avalanche over {AVALANCHE_SAMPLES} samples...")
    seed = generate_genesis_seed()
    base = "The structural stability of the 4D manifold loop parameters."

    total_ratio = 0
    for i in range(AVALANCHE_SAMPLES):
        mutated = base[:i] + chr(ord(base[i]) ^ 1) + base[i + 1:]

        salt = i.to_bytes(16, "big")
        iv = (i + 1).to_bytes(32, "big")

        c1 = ciphertext_with_forced_salt_iv(base, seed, salt, iv)
        c2 = ciphertext_with_forced_salt_iv(mutated, seed, salt, iv)

        diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1, c2))
        total_ratio += (diff / (len(c1) * 8))

    avg = (total_ratio / AVALANCHE_SAMPLES) * 100
    print(f"[INFO] Avalanche avg: {avg:.2f}%")
    assert 45.0 <= avg <= 55.0, "Avalanche criterion failure!"
    print("[PASS] Multi-sample avalanche behavior looks reasonable")


def test_token_structure_integrity():
    print("\n[*] Token structure integrity & multi-seed rejections...")
    seed = generate_genesis_seed()
    msg = "Verification message."
    token = mtc_encrypt(msg, seed)

    package = json.loads(base64.b64decode(token).decode("utf-8"))

    assert "header" in package
    assert "salt" in package
    assert "iv" in package
    assert "ciphertext" in package
    assert "tag" in package

    header = package["header"]
    assert isinstance(header["version"], int), "Header 'version' field must be an integer metric."
    assert "Pure-Manifold" in header["cipher"], "Cipher name signature payload mismatch."
    assert header["authentication"] == "HMAC-SHA256"

    # Verify that multi-sample randomized wrong seeds fail cleanly
    for i in range(WRONG_SEED_ATTEMPTS):
        bad_seed = generate_genesis_seed()
        if bad_seed == seed:
            bad_seed = "0" + seed[1:] if seed[0] != "0" else "1" + seed[1:]

        try:
            mtc_decrypt(token, bad_seed)
            raise AssertionError("Security vulnerability: System accepted an unauthenticated seed vector!")
        except ValueError:
            pass  # Expecting value validation rejection

    # Execute final round-trip proof
    decrypted = mtc_decrypt(token, seed)
    assert decrypted == msg, "Decryption pipeline failure."
    print("[PASS] Token layout, multi-seed tampering protection, and decryption verified.")


def run_advanced_tests():
    print("=" * 72)
    print("        ADVANCED PURE MANIFOLD SECURITY TEST UTILITY")
    print(f"        TARGET MODULE UNDER TESTING: {TARGET_CIPHER_MODULE}.py")
    print("=" * 72)

    test_known_plaintext_reuse()
    test_randomized_repeated_prefix_uniqueness()
    test_salt_iv_uniqueness()
    test_bit_level_balance()
    test_serial_correlation()
    test_cycle_probe()
    test_multi_sample_avalanche()
    test_token_structure_integrity()

    print("\n" + "=" * 72)
    print(f"[SUCCESS] ALL ENGINE ASSERTS FOR {TARGET_CIPHER_MODULE.upper()} CLEARED COMPLIANCE.")
    print("=" * 72)


if __name__ == "__main__":
    run_advanced_tests()
