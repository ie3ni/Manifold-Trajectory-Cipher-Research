import importlib
import math
import sys
from collections import Counter

# ============================================================
# CENTRAL TEST CONFIGURATION
# ============================================================
# Change this string to switch target modules: "main", "main_2", "main_3", etc.
TARGET_CIPHER_MODULE = "main_2"

# Existing structural configuration parameters preserved exactly
GENESIS_SEED = "9dc598e1de13406673664556e228a7bd89ca341818d1773f7c9442e4ef4e0061"

STREAM_LENGTH = 20_000
AVALANCHE_LENGTH = 4_096
CYCLE_STEPS = 10_000

TEST_SALT = b"A" * 16
TEST_IV = b"B" * 32

# ============================================================
# DYNAMIC MODULE IMPORT
# ============================================================
try:
    cipher_module = importlib.import_module(TARGET_CIPHER_MODULE)
    derive_keys = cipher_module.derive_keys
    PureManifoldCipher = cipher_module.PureManifoldCipher
    rotl64 = cipher_module.rotl64
    rotr64 = cipher_module.rotr64
    MASK64 = cipher_module.MASK64

    # main_2 uses inline pow() instead of mod_inverse; load conditionally to prevent errors
    mod_inverse = getattr(cipher_module, "mod_inverse", None)
except ImportError:
    print(f"[-] CRITICAL ERROR: Could not find or load '{TARGET_CIPHER_MODULE}.py'.")
    print("    Ensure the file exists in the same folder and the name matches exactly.")
    sys.exit(1)


# ============================================================
# METRIC HELPERS
# ============================================================

def bit_difference(a: bytes, b: bytes) -> int:
    max_len = max(len(a), len(b))
    a = a.ljust(max_len, b"\x00")
    b = b.ljust(max_len, b"\x00")

    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def hamming_rate(a: bytes, b: bytes) -> float:
    total_bits = max(len(a), len(b)) * 8
    if total_bits == 0:
        return 0.0
    return bit_difference(a, b) / total_bits


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


def bit_balance(data: bytes) -> float:
    ones = sum(bin(byte).count("1") for byte in data)
    return ones / (len(data) * 8)


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


def score_stream(data: bytes) -> dict:
    entropy = byte_entropy(data)
    chi = chi_square_score(data)
    balance = bit_balance(data)
    corr = serial_correlation(data)

    suspicion = 0

    if abs(entropy - 8.0) > 0.05:
        suspicion += 1

    if chi > 400:
        suspicion += 1

    if not (0.48 < balance < 0.52):
        suspicion += 1

    if abs(corr) > 0.04:
        suspicion += 1

    return {
        "entropy": entropy,
        "chi_square": chi,
        "bit_balance": balance,
        "serial_correlation": corr,
        "suspicion_score": suspicion,
    }


# ============================================================
# STREAM GENERATION
# ============================================================

def generate_stream(cipher_class, seed: str, salt: bytes, iv: bytes, length: int) -> bytes:
    encryption_key, _ = derive_keys(seed, salt)
    engine = cipher_class(encryption_key, iv)

    output = bytearray()

    for _ in range(length):
        k = engine.get_keystream_byte()
        output.append(k)
        engine.mutate_manifold(k)

    return bytes(output)


def cycle_probe(cipher_class, seed: str, salt: bytes, iv: bytes, steps: int) -> bool:
    encryption_key, _ = derive_keys(seed, salt)
    engine = cipher_class(encryption_key, iv)

    seen = set()

    for _ in range(steps):
        state = tuple(
            getattr(engine, name)
            for name in [
                "x", "y", "z", "w",
                "a", "b", "c", "d",
                "e", "f", "g", "h",
                "counter"
            ]
            if hasattr(engine, name)
        )

        if state in seen:
            return False

        seen.add(state)

        k = engine.get_keystream_byte()
        engine.mutate_manifold(k)

    return True


def iv_avalanche(cipher_class) -> float:
    iv1 = bytearray(TEST_IV)
    iv2 = bytearray(TEST_IV)
    iv2[0] ^= 1

    s1 = generate_stream(cipher_class, GENESIS_SEED, TEST_SALT, bytes(iv1), AVALANCHE_LENGTH)
    s2 = generate_stream(cipher_class, GENESIS_SEED, TEST_SALT, bytes(iv2), AVALANCHE_LENGTH)

    return hamming_rate(s1, s2)


# ============================================================
# ABLATION VARIANTS
# ============================================================

class WeakNoPrimeFieldCipher(PureManifoldCipher):
    """
    Removes prime-field nonlinear maps.
    Keeps ARX, cross-coupling, and permutation.
    """

    def _prime_field_round(self, absorbed_byte: int):
        m = absorbed_byte & 0xFF

        self.x = (self.x + self.y + m + self.counter) % self.MOD_X
        self.y = (self.y + self.z + m + self.counter) % self.MOD_Y
        self.z = (self.z + self.w + m + self.counter) % self.MOD_Z
        self.w = (self.w + self.x + m + self.counter) % self.MOD_W

        self._sanitize_states()


class WeakOneRoundCipher(PureManifoldCipher):
    """
    Reduces the six internal ARX/cross-couple/permutation rounds to one.
    """

    def _full_manifold_round(self, absorbed_byte: int):
        self._prime_field_round(absorbed_byte)

        self._arx_quarter_round()
        self._cross_couple_round(absorbed_byte)
        self._permutation_round()

        self.counter = (self.counter + 1) & MASK64
        self._sanitize_states()


class WeakNoPermutationCipher(PureManifoldCipher):
    """
    Removes the permutation round.
    Keeps prime-field maps, ARX, and cross-coupling.
    """

    def _full_manifold_round(self, absorbed_byte: int):
        self._prime_field_round(absorbed_byte)

        for _ in range(6):
            self._arx_quarter_round()
            self._cross_couple_round(absorbed_byte)

        self.counter = (self.counter + 1) & MASK64
        self._sanitize_states()


class WeakNoCrossCouplingCipher(PureManifoldCipher):
    """
    Removes cross-coupling between prime-field states and ARX states.
    """

    def _cross_couple_round(self, absorbed_byte: int):
        pass


class WeakNoCiphertextFeedbackCipher(PureManifoldCipher):
    """
    Ignores payload byte during mutation.
    This makes future state less dependent on ciphertext.
    """

    def mutate_manifold(self, payload_byte: int):
        self._full_manifold_round(0x00)
        self._full_manifold_round(0x5A)


class WeakLowDiffusionExtractorCipher(PureManifoldCipher):
    """
    Weakens output extraction.
    Uses only the lowest byte of a single state.
    """

    def _extract_byte_from_manifold(self) -> int:
        return self.a & 0xFF


class WeakSmallStateCipher(PureManifoldCipher):
    """
    Artificially collapses internal ARX states to 16 bits.
    This should degrade behavior if state size matters.
    """

    def _sanitize_states(self):
        super()._sanitize_states()

        self.a &= 0xFFFF
        self.b &= 0xFFFF
        self.c &= 0xFFFF
        self.d &= 0xFFFF
        self.e &= 0xFFFF
        self.f &= 0xFFFF
        self.g &= 0xFFFF
        self.h &= 0xFFFF


# ============================================================
# TEST RUNNER
# ============================================================

def test_cipher_variant(name: str, cipher_class):
    print("\n" + "-" * 72)
    print(f"Testing Variant: {name}")
    print("-" * 72)

    stream = generate_stream(
        cipher_class,
        GENESIS_SEED,
        TEST_SALT,
        TEST_IV,
        STREAM_LENGTH
    )

    metrics = score_stream(stream)
    avalanche = iv_avalanche(cipher_class)
    no_cycle = cycle_probe(cipher_class, GENESIS_SEED, TEST_SALT, TEST_IV, CYCLE_STEPS)

    print(f"Entropy:            {metrics['entropy']:.6f}")
    print(f"Chi-square:         {metrics['chi_square']:.2f}")
    print(f"Bit balance:        {metrics['bit_balance']:.6f}")
    print(f"Serial correlation: {metrics['serial_correlation']:.6f}")
    print(f"IV avalanche:       {avalanche:.2%}")
    print(f"No cycle detected:  {no_cycle}")
    print(f"Suspicion score:    {metrics['suspicion_score']}")

    weak_flags = 0

    if metrics["suspicion_score"] > 0:
        weak_flags += metrics["suspicion_score"]

    if not (0.40 < avalanche < 0.60):
        weak_flags += 1

    if not no_cycle:
        weak_flags += 2

    return {
        "name": name,
        "entropy": metrics["entropy"],
        "chi_square": metrics["chi_square"],
        "bit_balance": metrics["bit_balance"],
        "serial_correlation": metrics["serial_correlation"],
        "iv_avalanche": avalanche,
        "no_cycle": no_cycle,
        "suspicion_score": metrics["suspicion_score"],
        "weak_flags": weak_flags,
    }


def run_ablation_tests():
    print("=" * 72)
    print("        PURE MANIFOLD CIPHER ABLATION TEST SUITE")
    print(f"        TARGET MODULE UNDER TESTING: {TARGET_CIPHER_MODULE}.py")
    print("=" * 72)

    variants = [
        ("FULL PureManifoldCipher", PureManifoldCipher),
        ("WEAK No Prime Field", WeakNoPrimeFieldCipher),
        ("WEAK One Internal Round", WeakOneRoundCipher),
        ("WEAK No Permutation", WeakNoPermutationCipher),
        ("WEAK No Cross-Coupling", WeakNoCrossCouplingCipher),
        ("WEAK No Ciphertext Feedback", WeakNoCiphertextFeedbackCipher),
        ("WEAK Low-Diffusion Extractor", WeakLowDiffusionExtractorCipher),
        ("WEAK Small 16-bit ARX State", WeakSmallStateCipher),
    ]

    results = []

    for name, cipher_class in variants:
        result = test_cipher_variant(name, cipher_class)
        results.append(result)

    print("\n" + "=" * 72)
    print("        ABLATION SUMMARY")
    print("=" * 72)

    full = results[0]

    print(
        f"{'Variant':35} | {'Entropy':>8} | {'ChiSq':>8} | "
        f"{'Avalanche':>10} | {'Flags':>5}"
    )

    print("-" * 72)

    for r in results:
        print(
            f"{r['name'][:35]:35} | "
            f"{r['entropy']:8.4f} | "
            f"{r['chi_square']:8.2f} | "
            f"{r['iv_avalanche']:10.2%} | "
            f"{r['weak_flags']:5}"
        )

    print("\n" + "=" * 72)

    full_is_clean = full["weak_flags"] == 0

    weak_variants_show_degradation = any(
        r["weak_flags"] > full["weak_flags"]
        for r in results[1:]
    )

    if full_is_clean:
        print("[PASS] Full cipher showed clean behavior under ablation metrics.")
    else:
        print("[WARN] Full cipher showed suspicious behavior under ablation metrics.")

    if weak_variants_show_degradation:
        print("[PASS] At least one weakened variant degraded relative to the full cipher.")
        print("[INFO] These metrics detected measurable degradation in at least one removed layer.")
    else:
        print("[WARN] Weak variants did not clearly degrade under these tests.")
        print("[INFO] This does not prove the layers are useless, but stronger tests are needed.")

    print("=" * 72)
    print("[DONE] Ablation testing completed")
    print("=" * 72)


if __name__ == "__main__":
    run_ablation_tests()
