import os
import hmac
import json
import time
import base64
import hashlib
import sys
import importlib
from collections import Counter

# ============================================================
# CENTRAL TEST CONFIGURATION
# ============================================================
# Change this string to switch target modules: "main", "main_2", "main_3", etc.
TARGET_CIPHER_MODULE = "main_2"

# Existing structural configuration parameters preserved exactly
GENESIS_SEED = "9dc598e1de13406673664556e228a7bd89ca341818d1773f7c9442e4ef4e0061"

LONG_STREAM_BYTES = 50_000
POSITION_BIAS_SAMPLES = 50
POSITION_BIAS_LENGTH = 64
PERFORMANCE_SIZES = [1_000, 10_000, 50_000]

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
# UTILITIES & HELPER OPERATIONS
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


def token_ciphertext(token: str) -> bytes:
    return b64decode_padded(unpack_token(token)["ciphertext"])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def bit_difference(a: bytes, b: bytes) -> int:
    max_len = max(len(a), len(b))
    a = a.ljust(max_len, b"\x00")
    b = b.ljust(max_len, b"\x00")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def hamming_rate(a: bytes, b: bytes) -> float:
    total_bits = max(len(a), len(b)) * 8
    return bit_difference(a, b) / total_bits if total_bits else 0.0


def flip_one_hex_char(seed: str) -> str:
    chars = list(seed)
    chars[0] = "0" if chars[0] != "0" else "1"
    return "".join(chars)


def generate_keystream(seed: str, salt: bytes, iv: bytes, n: int) -> bytes:
    encryption_key, _ = derive_keys(seed, salt)
    engine = PureManifoldCipher(encryption_key, iv)

    stream = bytearray()

    for _ in range(n):
        k = engine.get_keystream_byte()
        stream.append(k)
        engine.mutate_manifold(k)

    return bytes(stream)


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

    # DYNAMIC METADATA DISCOVERY: Pulls the active module's complete header.
    token_sample = mtc_encrypt("test", genesis_seed)
    parsed_sample = unpack_token(token_sample)
    header = parsed_sample["header"]

    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")

    tag = hmac.new(
        authentication_key,
        header_bytes + salt + iv + ciphertext,
        hashlib.sha256
    ).digest()

    package = {
        "header": header,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
    }

    return pack_token(package)


# ============================================================
# ATTACK-STYLE SECURITY MATRIX
# ============================================================

def test_forced_salt_iv_reuse_warning():
    print("\n[*] Forced salt/IV reuse warning...")

    salt = b"S" * 16
    iv = b"I" * 32
    msg = "same plaintext under same salt and IV"

    c1 = token_ciphertext(encrypt_with_forced_salt_iv(msg, GENESIS_SEED, salt, iv))
    c2 = token_ciphertext(encrypt_with_forced_salt_iv(msg, GENESIS_SEED, salt, iv))

    assert c1 == c2

    print("[PASS] Forced salt/IV reuse produces identical ciphertext")
    print("[WARN] Salt and IV uniqueness are mandatory")


def test_known_plaintext_keystream_recovery_does_not_cross_messages():
    print("\n[*] Known-plaintext keystream recovery...")

    known_plaintext = b"ATTACK_AT_DAWN:" + b"A" * 128
    unknown_plaintext = b"ATTACK_AT_DAWN:" + b"B" * 128

    c1 = token_ciphertext(mtc_encrypt(known_plaintext.decode("utf-8"), GENESIS_SEED))
    c2 = token_ciphertext(mtc_encrypt(unknown_plaintext.decode("utf-8"), GENESIS_SEED))

    recovered_keystream = xor_bytes(c1, known_plaintext)
    attempted_plaintext = xor_bytes(c2, recovered_keystream)

    assert attempted_plaintext != unknown_plaintext

    similarity = sum(
        1 for a, b in zip(attempted_plaintext, unknown_plaintext)
        if a == b
    ) / len(unknown_plaintext)

    print(f"[INFO] Cross-message recovery similarity: {similarity:.2%}")
    assert similarity < 0.25

    print("[PASS] Recovered keystream from one message does not decrypt another")


def test_randomized_prefix_uniqueness():
    print("\n[*] Randomized shared-prefix uniqueness...")

    prefix = "COMMON_HEADER:"
    ciphertext_prefixes = set()

    for i in range(POSITION_BIAS_SAMPLES):
        msg = prefix + f"message-{i}-" + os.urandom(16).hex()
        c = token_ciphertext(mtc_encrypt(msg, GENESIS_SEED))
        ciphertext_prefixes.add(c[:len(prefix)])

    uniqueness_rate = len(ciphertext_prefixes) / POSITION_BIAS_SAMPLES

    print(f"[INFO] Prefix uniqueness rate: {uniqueness_rate:.2%}")
    assert uniqueness_rate > 0.90

    print("[PASS] Random salt/IV prevents shared plaintext prefixes from clustering across messages")


def test_genesis_seed_avalanche():
    print("\n[*] Genesis Seed avalanche...")

    msg = "Genesis Seed avalanche test message" * 8

    seed1 = GENESIS_SEED
    seed2 = flip_one_hex_char(GENESIS_SEED)

    salt = b"A" * 16
    iv = b"B" * 32

    c1 = token_ciphertext(encrypt_with_forced_salt_iv(msg, seed1, salt, iv))
    c2 = token_ciphertext(encrypt_with_forced_salt_iv(msg, seed2, salt, iv))

    rate = hamming_rate(c1, c2)

    print(f"[INFO] Seed avalanche rate: {rate:.2%}")
    assert 0.30 < rate < 0.70

    print("[PASS] Small Genesis Seed change causes large divergence")


def test_iv_avalanche():
    print("\n[*] IV avalanche...")

    msg = "IV avalanche test message" * 8

    salt = b"C" * 16
    iv1 = bytearray(b"D" * 32)
    iv2 = bytearray(iv1)
    iv2[0] ^= 1

    c1 = token_ciphertext(encrypt_with_forced_salt_iv(msg, GENESIS_SEED, salt, bytes(iv1)))
    c2 = token_ciphertext(encrypt_with_forced_salt_iv(msg, GENESIS_SEED, salt, bytes(iv2)))

    rate = hamming_rate(c1, c2)

    print(f"[INFO] IV avalanche rate: {rate:.2%}")
    assert 0.30 < rate < 0.70

    print("[PASS] Single-bit IV change causes large divergence")


def test_long_stream_bias():
    print(f"\n[*] Long-stream bias over {LONG_STREAM_BYTES} bytes...")

    stream = generate_keystream(GENESIS_SEED, b"L" * 16, b"M" * 32, LONG_STREAM_BYTES)

    counts = Counter(stream)
    expected = LONG_STREAM_BYTES / 256

    chi_square = sum(
        ((counts.get(i, 0) - expected) ** 2) / expected
        for i in range(256)
    )

    ones = sum(bin(byte).count("1") for byte in stream)
    bit_ratio = ones / (LONG_STREAM_BYTES * 8)

    values = list(stream)
    mean = sum(values) / len(values)

    numerator = sum(
        (values[i] - mean) * (values[i + 1] - mean)
        for i in range(len(values) - 1)
    )

    denominator = sum((v - mean) ** 2 for v in values)
    serial_corr = numerator / denominator

    print(f"[INFO] Chi-square: {chi_square:.2f}")
    print(f"[INFO] Bit-one ratio: {bit_ratio:.4f}")
    print(f"[INFO] Serial correlation: {serial_corr:.6f}")

    assert chi_square < 450
    assert 0.48 < bit_ratio < 0.52
    assert abs(serial_corr) < 0.04

    print("[PASS] Long-stream output shows no obvious simple statistical weakness")


def test_position_bias():
    print("\n[*] Block-position bias...")

    position_counts = [Counter() for _ in range(POSITION_BIAS_LENGTH)]

    for _ in range(POSITION_BIAS_SAMPLES):
        msg = os.urandom(POSITION_BIAS_LENGTH).hex()
        c = token_ciphertext(mtc_encrypt(msg, GENESIS_SEED))

        for pos in range(min(POSITION_BIAS_LENGTH, len(c))):
            position_counts[pos][c[pos]] += 1

    suspicious_positions = 0

    for counts in position_counts:
        most_common_count = counts.most_common(1)[0][1]

        if most_common_count > POSITION_BIAS_SAMPLES * 0.18:
            suspicious_positions += 1

    print(f"[INFO] Suspicious biased positions: {suspicious_positions}")
    assert suspicious_positions <= 4

    print("[PASS] No obvious position-specific byte bias detected")


def test_performance_benchmark():
    print("\n[*] Performance benchmark...")

    for size in PERFORMANCE_SIZES:
        msg = "A" * size

        start_encrypt = time.perf_counter()
        token = mtc_encrypt(msg, GENESIS_SEED)
        end_encrypt = time.perf_counter()

        start_decrypt = time.perf_counter()
        recovered = mtc_decrypt(token, GENESIS_SEED)
        end_decrypt = time.perf_counter()

        assert recovered == msg

        print(
            f"[INFO] Size: {size:>8} bytes | "
            f"Encrypt: {end_encrypt - start_encrypt:.4f}s | "
            f"Decrypt: {end_decrypt - start_decrypt:.4f}s"
        )

    print("[PASS] Performance benchmark completed")


def test_tampered_header_rejected():
    print("\n[*] Tampered-header rejection...")

    token = mtc_encrypt("header tamper test", GENESIS_SEED)
    package = unpack_token(token)

    package["header"]["iterations"] = 1
    tampered = pack_token(package)

    try:
        mtc_decrypt(tampered, GENESIS_SEED)
    except ValueError:
        pass
    else:
        raise AssertionError("Tampered header was accepted")

    print("[PASS] Tampered header rejected")


def run_attack_tests():
    print("=" * 72)
    print("        PURE MANIFOLD ATTACK-STYLE SECURITY TESTS")
    print(f"        TARGET MODULE UNDER TESTING: {TARGET_CIPHER_MODULE}.py")
    print("=" * 72)

    test_forced_salt_iv_reuse_warning()
    test_known_plaintext_keystream_recovery_does_not_cross_messages()
    test_randomized_prefix_uniqueness()
    test_genesis_seed_avalanche()
    test_iv_avalanche()
    test_long_stream_bias()
    test_position_bias()
    test_performance_benchmark()
    test_tampered_header_rejected()

    print("=" * 72)
    print(f"[SUCCESS] Attack-style security tests for {TARGET_CIPHER_MODULE.upper()} completed")
    print("=" * 72)


if __name__ == "__main__":
    run_attack_tests()
