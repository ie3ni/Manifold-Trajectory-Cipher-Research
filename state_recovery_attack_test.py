import os
import math
import random
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

STREAM_LENGTH = 50_000
PREDICTION_WINDOW = 4
PREDICTION_TRIALS = 5_000

# ============================================================
# DYNAMIC MODULE IMPORT
# ============================================================
try:
    cipher_module = importlib.import_module(TARGET_CIPHER_MODULE)
    derive_keys = cipher_module.derive_keys
    PureManifoldCipher = cipher_module.PureManifoldCipher
except ImportError:
    print(f"[-] CRITICAL ERROR: Could not find or load '{TARGET_CIPHER_MODULE}.py'.")
    print("    Ensure the file exists in the same folder and the name matches exactly.")
    sys.exit(1)


# ============================================================
# HELPERS
# ============================================================

def generate_nmtc_stream(seed: str, salt: bytes, iv: bytes, length: int) -> bytes:
    encryption_key, _ = derive_keys(seed, salt)
    engine = PureManifoldCipher(encryption_key, iv)

    output = bytearray()

    for _ in range(length):
        k = engine.get_keystream_byte()
        output.append(k)
        engine.mutate_manifold(k)

    return bytes(output)


def byte_entropy(data: bytes) -> float:
    counts = Counter(data)
    total = len(data)

    entropy = 0.0

    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def chi_square_score(data: bytes) -> float:
    counts = Counter(data)
    expected = len(data) / 256

    return sum(
        ((counts.get(i, 0) - expected) ** 2) / expected
        for i in range(256)
    )


def serial_correlation(data: bytes) -> float:
    values = list(data)
    mean = sum(values) / len(values)

    numerator = sum(
        (values[i] - mean) * (values[i + 1] - mean)
        for i in range(len(values) - 1)
    )

    denominator = sum((v - mean) ** 2 for v in values)

    if denominator == 0:
        return 0.0

    return numerator / denominator


def bit_balance(data: bytes) -> float:
    ones = sum(bin(byte).count("1") for byte in data)
    total_bits = len(data) * 8
    return ones / total_bits


# ============================================================
# ATTACK 1: BASIC DISTINGUISHER
# ============================================================

def basic_distinguisher_score(data: bytes) -> dict:
    entropy = byte_entropy(data)
    chi = chi_square_score(data)
    corr = serial_correlation(data)
    balance = bit_balance(data)

    score = 0

    if abs(entropy - 8.0) > 0.03:
        score += 1

    if chi > 350:
        score += 1

    if abs(corr) > 0.02:
        score += 1

    if not (0.49 < balance < 0.51):
        score += 1

    return {
        "entropy": entropy,
        "chi_square": chi,
        "serial_correlation": corr,
        "bit_balance": balance,
        "suspicion_score": score,
    }


def attack_basic_distinguisher():
    print("\n" + "=" * 72)
    print("ATTACK 1: BASIC RANDOMNESS DISTINGUISHER")
    print("=" * 72)

    nmtc_stream = generate_nmtc_stream(
        GENESIS_SEED,
        b"A" * 16,
        b"B" * 32,
        STREAM_LENGTH
    )

    random_stream = os.urandom(STREAM_LENGTH)

    nmtc_score = basic_distinguisher_score(nmtc_stream)
    random_score = basic_distinguisher_score(random_stream)

    print("\n[+] NMTC Stream Metrics")
    for key, value in nmtc_score.items():
        print(f"{key}: {value}")

    print("\n[+] os.urandom Stream Metrics")
    for key, value in random_score.items():
        print(f"{key}: {value}")

    if nmtc_score["suspicion_score"] <= random_score["suspicion_score"] + 1:
        print("\n[PASS] Basic distinguisher did not clearly separate NMTC from randomness.")
    else:
        print("\n[WARN] NMTC looked more suspicious than os.urandom under simple metrics.")


# ============================================================
# ATTACK 2: N-GRAM FUTURE BYTE PREDICTION
# ============================================================

def build_ngram_predictor(data: bytes, window: int) -> dict:
    table = {}

    for i in range(len(data) - window):
        key = data[i:i + window]
        next_byte = data[i + window]

        if key not in table:
            table[key] = Counter()

        table[key][next_byte] += 1

    predictor = {}

    for key, counter in table.items():
        predictor[key] = counter.most_common(1)[0][0]

    return predictor


def test_ngram_prediction(train: bytes, test: bytes, window: int) -> float:
    predictor = build_ngram_predictor(train, window)

    correct = 0
    total = 0

    for i in range(len(test) - window):
        key = test[i:i + window]

        if key in predictor:
            predicted = predictor[key]
            actual = test[i + window]

            if predicted == actual:
                correct += 1

            total += 1

    if total == 0:
        return 0.0

    return correct / total


def attack_ngram_prediction():
    print("\n" + "=" * 72)
    print("ATTACK 2: N-GRAM FUTURE BYTE PREDICTION")
    print("=" * 72)

    train = generate_nmtc_stream(
        GENESIS_SEED,
        b"C" * 16,
        b"D" * 32,
        STREAM_LENGTH
    )

    test = generate_nmtc_stream(
        GENESIS_SEED,
        b"E" * 16,
        b"F" * 32,
        STREAM_LENGTH
    )

    accuracy = test_ngram_prediction(train, test, PREDICTION_WINDOW)

    random_baseline = 1 / 256

    print(f"[INFO] Prediction window: {PREDICTION_WINDOW}")
    print(f"[INFO] NMTC prediction accuracy: {accuracy:.6%}")
    print(f"[INFO] Random baseline accuracy: {random_baseline:.6%}")

    if accuracy < random_baseline * 3:
        print("[PASS] N-gram predictor did not meaningfully predict future bytes.")
    else:
        print("[WARN] N-gram predictor performed above random expectation.")


# ============================================================
# ATTACK 3: SAME-STREAM SELF-PREDICTION
# ============================================================

def attack_same_stream_self_prediction():
    print("\n" + "=" * 72)
    print("ATTACK 3: SAME-STREAM SELF-PREDICTION")
    print("=" * 72)

    stream = generate_nmtc_stream(
        GENESIS_SEED,
        b"G" * 16,
        b"H" * 32,
        STREAM_LENGTH * 2
    )

    train = stream[:STREAM_LENGTH]
    test = stream[STREAM_LENGTH:]

    accuracy = test_ngram_prediction(train, test, PREDICTION_WINDOW)
    random_baseline = 1 / 256

    print(f"[INFO] Same-stream prediction accuracy: {accuracy:.6%}")
    print(f"[INFO] Random baseline accuracy: {random_baseline:.6%}")

    if accuracy < random_baseline * 3:
        print("[PASS] Same-stream future bytes were not meaningfully predictable.")
    else:
        print("[WARN] Same-stream prediction exceeded random expectation.")


# ============================================================
# ATTACK 4: BYTE FREQUENCY POSITION PREDICTION
# ============================================================

def attack_position_prediction():
    print("\n" + "=" * 72)
    print("ATTACK 4: POSITION-BASED BYTE PREDICTION")
    print("=" * 72)

    streams = []

    for i in range(100):
        salt = i.to_bytes(16, "big")
        iv = (i + 10_000).to_bytes(32, "big")

        streams.append(
            generate_nmtc_stream(
                GENESIS_SEED,
                salt,
                iv,
                256
            )
        )

    position_tables = []

    for pos in range(256):
        counter = Counter(stream[pos] for stream in streams[:80])
        most_likely = counter.most_common(1)[0][0]
        position_tables.append(most_likely)

    correct = 0
    total = 0

    for stream in streams[80:]:
        for pos in range(256):
            predicted = position_tables[pos]
            actual = stream[pos]

            if predicted == actual:
                correct += 1

            total += 1

    accuracy = correct / total
    random_baseline = 1 / 256

    print(f"[INFO] Position predictor accuracy: {accuracy:.6%}")
    print(f"[INFO] Random baseline accuracy: {random_baseline:.6%}")

    if accuracy < random_baseline * 3:
        print("[PASS] Byte position did not meaningfully predict output.")
    else:
        print("[WARN] Position predictor exceeded random expectation.")


# ============================================================
# ATTACK 5: NEARBY IV RELATIONSHIP TEST
# ============================================================

def hamming_rate(a: bytes, b: bytes) -> float:
    max_len = max(len(a), len(b))
    a = a.ljust(max_len, b"\x00")
    b = b.ljust(max_len, b"\x00")

    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    return diff / (max_len * 8)


def attack_nearby_iv_relation():
    print("\n" + "=" * 72)
    print("ATTACK 5: NEARBY IV RELATIONSHIP TEST")
    print("=" * 72)

    salt = b"I" * 16

    iv1 = bytearray(b"J" * 32)
    iv2 = bytearray(iv1)

    iv2[0] ^= 1

    stream1 = generate_nmtc_stream(
        GENESIS_SEED,
        salt,
        bytes(iv1),
        STREAM_LENGTH
    )

    stream2 = generate_nmtc_stream(
        GENESIS_SEED,
        salt,
        bytes(iv2),
        STREAM_LENGTH
    )

    rate = hamming_rate(stream1, stream2)

    print(f"[INFO] Hamming distance between nearby-IV streams: {rate:.2%}")

    if 0.45 < rate < 0.55:
        print("[PASS] Nearby IVs produce strongly divergent streams.")
    else:
        print("[WARN] Nearby IVs produced unusual stream similarity/divergence.")


# ============================================================
# RUNNER
# ============================================================

def run_state_recovery_attacks():
    print("=" * 72)
    print("        PURE MANIFOLD STATE RECOVERY / DISTINGUISHER ATTACKS")
    print(f"        TARGET MODULE UNDER TESTING: {TARGET_CIPHER_MODULE}.py")
    print("=" * 72)

    attack_basic_distinguisher()
    attack_ngram_prediction()
    attack_same_stream_self_prediction()
    attack_position_prediction()
    attack_nearby_iv_relation()

    print("\n" + "=" * 72)
    print(f"[DONE] State recovery / distinguisher attack suite for {TARGET_CIPHER_MODULE.upper()} completed")
    print("=" * 72)


if __name__ == "__main__":
    run_state_recovery_attacks()