import os
import hmac
import json
import base64
import hashlib
import secrets
from typing import Tuple
from string import hexdigits

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

MASK64 = 0xFFFFFFFFFFFFFFFF


def rotl64(value: int, shift: int) -> int:
    value &= MASK64
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def rotr64(value: int, shift: int) -> int:
    value &= MASK64
    return ((value >> shift) | (value << (64 - shift))) & MASK64


def generate_genesis_seed() -> str:
    return secrets.token_hex(32)


def normalize_genesis_seed(genesis_seed: str) -> str:
    if not isinstance(genesis_seed, str):
        raise ValueError("Genesis Seed must be a 64-character hexadecimal string.")

    normalized = genesis_seed.strip().lower()

    if len(normalized) != 64 or any(char not in hexdigits for char in normalized):
        raise ValueError("Genesis Seed must be a 64-character hexadecimal string.")

    return normalized


# ============================================================
# NONLINEAR MANIFOLD CIPHER ENGINE (OPTIMIZED)
# ============================================================

class PureManifoldCipher:
    def __init__(self, encryption_key: bytes, iv: bytes):
        self.MOD_X = 2147483647
        self.MOD_Y = 4294967291
        self.MOD_Z = 9223372036854775783
        self.MOD_W = 18446744073709551557

        seed_material = hashlib.pbkdf2_hmac(
            "sha256",
            encryption_key,
            iv,
            10_000,
            dklen=64
        )

        self.x = int.from_bytes(seed_material[0:8], "big") % self.MOD_X
        self.y = int.from_bytes(seed_material[8:16], "big") % self.MOD_Y
        self.z = int.from_bytes(seed_material[16:32], "big") % self.MOD_Z
        self.w = int.from_bytes(seed_material[32:48], "big") % self.MOD_W
        self.counter = int.from_bytes(seed_material[48:56], "big")

        self.a = int.from_bytes(seed_material[0:8], "big") & MASK64
        self.b = int.from_bytes(seed_material[8:16], "big") & MASK64
        self.c = int.from_bytes(seed_material[16:24], "big") & MASK64
        self.d = int.from_bytes(seed_material[24:32], "big") & MASK64
        self.e = int.from_bytes(seed_material[32:40], "big") & MASK64
        self.f = int.from_bytes(seed_material[40:48], "big") & MASK64
        self.g = int.from_bytes(seed_material[48:56], "big") & MASK64
        self.h = int.from_bytes(seed_material[56:64], "big") & MASK64

        self._sanitize_states()

        for _ in range(16):
            self._full_manifold_round(0xA5)

    def _sanitize_states(self):
        if self.x == 0: self.x = 1
        if self.y == 0: self.y = 1
        if self.z == 0: self.z = 1
        if self.w == 0: self.w = 1

        self.a &= MASK64
        self.b &= MASK64
        self.c &= MASK64
        self.d &= MASK64
        self.e &= MASK64
        self.f &= MASK64
        self.g &= MASK64
        self.h &= MASK64

    def _prime_field_round(self, absorbed_byte: int):
        """
        Advances the 4D prime manifold coordinates.
        Uses Python's native C-level Extended Euclidean algorithm for optimized inverses.
        """
        # Formulate targets modulo their fields to prepare for inversion
        val_x = (self.x + absorbed_byte + self.counter + 1) % self.MOD_X
        val_y = (self.y + self.x + absorbed_byte + 1) % self.MOD_Y
        val_z = (self.z + self.y + absorbed_byte + 1) % self.MOD_Z
        val_w = (self.w + self.z + absorbed_byte + 1) % self.MOD_W

        # Hyper-optimized modular inversion + zero safety fallbacks
        x_inv = pow(val_x if val_x != 0 else 1, -1, self.MOD_X)
        y_inv = pow(val_y if val_y != 0 else 1, -1, self.MOD_Y)
        z_inv = pow(val_z if val_z != 0 else 1, -1, self.MOD_Z)
        w_inv = pow(val_w if val_w != 0 else 1, -1, self.MOD_W)

        new_x = (
            pow(self.x + absorbed_byte + self.counter, 3, self.MOD_X)
            + y_inv
            + self.y
            + (self.a % self.MOD_X)
        ) % self.MOD_X

        new_y = (
            pow(self.y + self.x + absorbed_byte + self.counter, 5, self.MOD_Y)
            + z_inv
            + self.z
            + (self.b % self.MOD_Y)
        ) % self.MOD_Y

        new_z = (
            pow(self.z + self.y + self.counter + absorbed_byte, 3, self.MOD_Z)
            + w_inv
            + self.w
            + (self.c % self.MOD_Z)
        ) % self.MOD_Z

        new_w = (
            pow(self.w + self.z + absorbed_byte + self.counter, 5, self.MOD_W)
            + x_inv
            + self.x
            + (self.d % self.MOD_W)
        ) % self.MOD_W

        self.x, self.y, self.z, self.w = new_x, new_y, new_z, new_w
        self._sanitize_states()

    def _arx_quarter_round(self):
        self.a = (self.a + self.b + self.x) & MASK64
        self.d ^= self.a
        self.d = rotl64(self.d, 32)

        self.c = (self.c + self.d + self.y) & MASK64
        self.b ^= self.c
        self.b = rotl64(self.b, 24)

        self.e = (self.e + self.f + self.z) & MASK64
        self.h ^= self.e
        self.h = rotl64(self.h, 16)

        self.g = (self.g + self.h + self.w) & MASK64
        self.f ^= self.g
        self.f = rotl64(self.f, 63)

        self.a = (self.a + self.f + self.counter) & MASK64
        self.h ^= self.a
        self.h = rotl64(self.h, 41)

        self.e = (self.e + self.b + self.x + self.z) & MASK64
        self.d ^= self.e
        self.d = rotl64(self.d, 17)

    def _cross_couple_round(self, absorbed_byte: int):
        m = absorbed_byte & 0xFF

        self.a ^= ((self.x << 33) | self.y | m) & MASK64
        self.b = (self.b + rotl64(self.z & MASK64, 19) + m) & MASK64
        self.c ^= rotr64((self.w + self.counter) & MASK64, 23)
        self.d = (self.d + self.a + self.x + m) & MASK64

        self.e ^= rotl64((self.y + self.z + m) & MASK64, 29)
        self.f = (self.f + self.e + self.w + self.counter) & MASK64
        self.g ^= rotr64((self.x * 0x9E3779B97F4A7C15) & MASK64, 31)
        self.h = (self.h + self.g + self.z + m) & MASK64

    def _permutation_round(self):
        self.a, self.b, self.c, self.d = self.c, self.d, self.a, self.b
        self.e, self.f, self.g, self.h = self.g, self.h, self.e, self.f

        self.a ^= rotl64(self.e, 7)
        self.b = (self.b + rotr64(self.f, 11)) & MASK64
        self.c ^= rotl64(self.g, 13)
        self.d = (self.d + rotr64(self.h, 17)) & MASK64

        self.e ^= rotl64(self.a, 19)
        self.f = (self.f + rotr64(self.b, 23)) & MASK64
        self.g ^= rotl64(self.c, 29)
        self.h = (self.h + rotr64(self.d, 31)) & MASK64

    def _full_manifold_round(self, absorbed_byte: int):
        self._prime_field_round(absorbed_byte)

        for _ in range(6):
            self._arx_quarter_round()
            self._cross_couple_round(absorbed_byte)
            self._permutation_round()

        self.counter = (self.counter + 1) & MASK64
        self._sanitize_states()

    def _extract_byte_from_manifold(self) -> int:
        out = (
            self.a
            ^ rotr64(self.b, 7)
            ^ rotl64(self.c, 13)
            ^ rotr64(self.d, 29)
            ^ self.e
            ^ rotl64(self.f, 37)
            ^ rotr64(self.g, 43)
            ^ self.h
            ^ self.x
            ^ self.y
            ^ self.z
            ^ self.w
            ^ self.counter
        ) & MASK64

        out ^= out >> 33
        out = (out * 0xff51afd7ed558ccd) & MASK64
        out ^= out >> 33
        out = (out * 0xc4ceb9fe1a85ec53) & MASK64
        out ^= out >> 33

        return out & 0xFF

    def get_keystream_byte(self) -> int:
        self._full_manifold_round(0x00)
        self._full_manifold_round(0x5A)
        return self._extract_byte_from_manifold()

    def mutate_manifold(self, payload_byte: int):
        self._full_manifold_round(payload_byte)
        self._full_manifold_round(payload_byte ^ 0xA5)


# ============================================================
# KEY DERIVATION
# ============================================================

def derive_keys(genesis_seed: str, salt: bytes) -> Tuple[bytes, bytes]:
    genesis_seed = normalize_genesis_seed(genesis_seed)

    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        genesis_seed.encode("ascii"),
        salt,
        600_000,
        dklen=64
    )
    return key_material[:32], key_material[32:]


# ============================================================
# ENCRYPTION
# ============================================================

def mtc_encrypt(message: str, genesis_seed: str) -> str:
    plaintext = message.encode("utf-8")
    salt = os.urandom(16)
    iv = os.urandom(32)

    encryption_key, authentication_key = derive_keys(genesis_seed, salt)
    engine = PureManifoldCipher(encryption_key, iv)

    ciphertext = bytearray()
    for plain_byte in plaintext:
        keystream = engine.get_keystream_byte()
        cipher_byte = plain_byte ^ keystream
        ciphertext.append(cipher_byte)
        engine.mutate_manifold(cipher_byte)

    ciphertext = bytes(ciphertext)

    header = {
        "version": 6,
        "cipher": "Pure-Manifold-Trajectory-Cipher-V6",
        "seed_type": "Genesis Seed",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": 600_000,
        "state": "x-y-z-w plus a-b-c-d-e-f-g-h",
        "mixing": "prime-field-arx-permutation-cross-coupling",
        "keystream": "optimized-gcd-manifold-derived",
        "authentication": "HMAC-SHA256"
    }

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

    return base64.b64encode(json.dumps(package).encode("utf-8")).decode("utf-8")


# ============================================================
# DECRYPTION
# ============================================================

def mtc_decrypt(token: str, genesis_seed: str) -> str:
    package = json.loads(base64.b64decode(token).decode("utf-8"))

    header = package["header"]
    salt = base64.b64decode(package["salt"])
    iv = base64.b64decode(package["iv"])
    ciphertext = base64.b64decode(package["ciphertext"])
    received_tag = base64.b64decode(package["tag"])

    encryption_key, authentication_key = derive_keys(genesis_seed, salt)
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")

    expected_tag = hmac.new(
        authentication_key,
        header_bytes + salt + iv + ciphertext,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(received_tag, expected_tag):
        raise ValueError("Authentication failed. Wrong Genesis Seed or tampered ciphertext.")

    engine = PureManifoldCipher(encryption_key, iv)

    plaintext = bytearray()
    for cipher_byte in ciphertext:
        keystream = engine.get_keystream_byte()
        plain_byte = cipher_byte ^ keystream
        plaintext.append(plain_byte)
        engine.mutate_manifold(cipher_byte)

    return plaintext.decode("utf-8")


# ============================================================
# INTERACTIVE RUNNER
# ============================================================

if __name__ == "__main__":
    print("=" * 72)
    print("    PURE MANIFOLD TRAJECTORY CIPHER CONSOLE (GCD OPTIMIZED)")
    print("=" * 72)

    print("\nChoose Genesis Seed mode:")
    print("[1] Enter existing Genesis Seed")
    print("[2] Generate new random Genesis Seed")

    mode = input("\n[>] Select mode 1 or 2: ").strip()

    if mode == "2":
        genesis_seed = generate_genesis_seed()
        print("\n[+] NEW GENESIS SEED GENERATED")
        print("[!] Save this seed. Without it, decryption is impossible.")
        print(f"[+] Genesis Seed: {genesis_seed}")
    else:
        genesis_seed = input("\n[>] Enter Genesis Seed: ").strip()
        if not genesis_seed:
            raise ValueError("Genesis Seed cannot be empty.")

    message = input("\n[>] Enter a message to encrypt: ")

    if not message:
        message = "Default baseline optimization manifold package."
        print(f"[*] Empty input detected. Using default: '{message}'")

    print("\n[*] Initializing optimized nonlinear manifold orbit...")
    print("[*] Computing lightweight C-accelerated modular division chains...")

    encrypted_token = mtc_encrypt(message, genesis_seed)

    print("-" * 72)
    print("[+] ENCRYPTED AUTHENTICATED TOKEN:")
    print(encrypted_token)
    print("-" * 72)

    print("\n[*] Running local decrypt verification...")
    recovered_text = mtc_decrypt(encrypted_token, genesis_seed)

    print(f"[+] DECRYPTION SUCCESSFUL: \"{recovered_text}\"")
    print("=" * 72)
