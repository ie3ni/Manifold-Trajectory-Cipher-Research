# Pure Manifold Trajectory Cipher (PMTC)

> **Research and educational use only. No warranty is provided regarding cryptographic security.**  
> PMTC is not a replacement for AES-256, ChaCha20, XChaCha20, or any standardized cipher.

---

## Overview

The Pure Manifold Trajectory Cipher (PMTC) is an experimental cryptographic research project exploring whether a nonlinear dynamical system — built from prime-field arithmetic, manifold-inspired high-dimensional state space, ARX transformations (Addition-Rotation-XOR), and cross-coupled state trajectories — can generate cryptographically useful keystreams.

Unlike conventional stream ciphers, PMTC treats encryption as the evolution of a high-dimensional nonlinear state manifold whose trajectory is continuously perturbed by ciphertext feedback.

This is more or less a research project where I am learning as I go more about coding and coding architecture and about cryptography by playing with different ideas. 

It is computationally heavy, so it may not have practical use cases. A possible future direction is to explore whether ideas from this symmetric-key experiment can inform public-key research.

---

## Design Goals


- Explore manifold-inspired nonlinear state evolution
- Utilize prime-field arithmetic as a source of algebraic complexity
- Introduce cross-coupled state trajectories
- Investigate whether complex deterministic dynamics can produce cryptographically useful behavior
- Probe behavior under statistical, differential, and prediction-style tests

---

## High-Level Architecture

```
Genesis Seed
      ↓
PBKDF2-HMAC-SHA256 Key Derivation  (600,000 iterations)
      ↓
Prime Field Manifold Initialization (secondary PBKDF2, 10,000 iterations + 16 warm-up rounds)
      ↓
Nonlinear State Evolution
      ↓
  ┌─────────────────────────────────────────────┐
  │  Per Full Manifold Round:                   │
  │    Prime Field Round                        │
  │    × 6: ARX Quarter Round                  │
  │          Cross-Coupling Round               │
  │          Permutation Round                  │
  └─────────────────────────────────────────────┘
      ↓
Keystream Extraction  (2 manifold rounds + finalizer per byte)
      ↓
XOR Encryption + Ciphertext Feedback (2 manifold rounds per byte)
      ↓
HMAC-SHA256 Authentication
```

---

## Internal State

The system maintains two interacting state spaces, totaling 12 state variables plus a counter (13 values total).

### Prime Field States

Four variables, each evolving inside its own large prime field:

| Variable | Prime Modulus |
|----------|---------------|
| `x` | `2147483647` |
| `y` | `4294967291` |
| `z` | `9223372036854775783` |
| `w` | `18446744073709551557` |

```python
MOD_X = 2147483647
MOD_Y = 4294967291
MOD_Z = 9223372036854775783
MOD_W = 18446744073709551557
```

Each state is initialized from the seed material and sanitized to be non-zero (zero is replaced with 1) before any rounds run.

### ARX States

Eight 64-bit integer variables: `a, b, c, d, e, f, g, h`.

These provide fast diffusion and mixing across the full state space.

---

## Genesis Seed

The Genesis Seed is the master secret from which all keys are derived.

```
9dc598e1de13406673664556e228a7bd89ca341818d1773f7c9442e4ef4e0061
```

It is a 64-character hex string (32 random bytes) generated via `secrets.token_hex(32)`. The implementation rejects malformed or short seeds. It is **never transmitted**. Without it, decryption is infeasible under the assumptions of the experiment.

---

## Key Derivation

### Stage 1 — Main KDF

The Genesis Seed is processed with `PBKDF2-HMAC-SHA256`:

| Parameter | Value |
|-----------|-------|
| Input | Normalized Genesis Seed (ASCII hex) |
| Salt | Random 16-byte salt |
| Iterations | 600,000 |
| Output | 64 bytes |

The 64-byte output is split into:
- **Bytes 0–31** → 32-byte encryption key
- **Bytes 32–63** → 32-byte authentication key

### Stage 2 — Cipher Initialization KDF

Inside `PureManifoldCipher.__init__`, a second `PBKDF2-HMAC-SHA256` pass is run:

| Parameter | Value |
|-----------|-------|
| Input | Encryption key |
| Salt | Random 32-byte IV |
| Iterations | 10,000 |
| Output | 64 bytes |

This 64-byte seed material initializes all 12 state variables (`x, y, z, w, a, b, c, d, e, f, g, h`) and the counter. After initialization, **16 warm-up rounds** are executed with payload byte `0xA5` to mix the state before any keystream is produced.

---

## Cipher Layers

### Prime Field Round

The primary source of nonlinear behavior. Each call updates all four prime-field variables using:

- Modular exponentiation: `pow(x, 3, MOD_X)`, `pow(y, 5, MOD_Y)`, etc.
- Modular inverse: `mod_inverse(...)` via Fermat's little theorem (`pow(v, p-2, p)`) in `main.py`; native modular inversion via `pow(v, -1, prime)` in `main_2.py`. If an inverse target is `0 mod p`, the implementation substitutes `1` as a deterministic fallback, so that transition is a defined rule rather than a true inverse.
- Cross-state interaction: ARX states feed into prime-field updates

Conceptually:

```
x(n+1) = f(x, y, z, w, a, counter, payload)
```

The modular inverse introduces strong nonlinearity while remaining deterministic:

```
a × a⁻¹ ≡ 1 (mod p)
```

### ARX Quarter Round

Six ARX quarter rounds execute per full manifold round. Each round applies Addition, Rotation, and XOR to all eight ARX variables, with prime field states injected directly:

```python
a = (a + b + x) & MASK64
d ^= a
d = rotl64(d, 32)

c = (c + d + y) & MASK64
b ^= c
b = rotl64(b, 24)
# ... continued across all 8 variables
```

ARX constructions provide fast mixing and are commonly used as diffusion layers. Their presence here does not by itself prove resistance to linear attacks.

### Cross-Coupling Round

Executed once per ARX iteration, this layer directly ties the prime-field states into the ARX variables and vice versa:

```python
a ^= ((x << 33) | y | m) & MASK64
b  = (b + rotl64(z & MASK64, 19) + m) & MASK64
g ^= rotr64((x * 0x9E3779B97F4A7C15) & MASK64, 31)
```

This is intended to make independent analysis of either subsystem harder by tying the update paths together.

### Permutation Round

Executed once per ARX iteration. Variables are swapped and then mixed with rotations:

```python
a, b, c, d = c, d, a, b
e, f, g, h = g, h, e, f

a ^= rotl64(e, 7)
b  = (b + rotr64(f, 11)) & MASK64
# ...
```

This increases diffusion and reduces the chance that local structure survives across rounds.

### Full Manifold Round

One complete round consists of:

1. One prime field round
2. Six iterations of:
   - ARX quarter round
   - Cross-coupling round
   - Permutation round
3. Counter increment
4. State sanitization

---

## Keystream Extraction

### Per-Byte Cost

For each keystream byte, `get_keystream_byte()` executes **two full manifold rounds** before extracting:

```python
self._full_manifold_round(0x00)
self._full_manifold_round(0x5A)
return self._extract_byte_from_manifold()
```

### Extractor

The extractor combines the 12 state variables plus the counter with rotations and XOR, then applies a 3-step integer finalizer (similar to MurmurHash3/xxHash) to collapse the 64-bit combined value to a single output byte:

```python
out = (a ^ rotr64(b,7) ^ rotl64(c,13) ^ rotr64(d,29)
       ^ e ^ rotl64(f,37) ^ rotr64(g,43) ^ h
       ^ x ^ y ^ z ^ w ^ counter) & MASK64

out ^= out >> 33
out  = (out * 0xff51afd7ed558ccd) & MASK64
out ^= out >> 33
out  = (out * 0xc4ceb9fe1a85ec53) & MASK64
out ^= out >> 33

return out & 0xFF
```

---

## Encryption and Decryption

### Encryption

For each plaintext byte:

```
ciphertext_byte = plaintext_byte XOR keystream_byte
```

After each byte is encrypted, `mutate_manifold(ciphertext_byte)` runs **two additional full manifold rounds**, injecting the ciphertext byte back into the state:

```python
self._full_manifold_round(payload_byte)
self._full_manifold_round(payload_byte ^ 0xA5)
```

This creates ciphertext feedback: future state evolution depends on all previous ciphertext output.

### Decryption

Decryption is structurally identical — the same ciphertext byte is used to mutate the manifold in both directions, keeping the state synchronized:

```
plaintext_byte = ciphertext_byte XOR keystream_byte
mutate_manifold(ciphertext_byte)   # same call as encryption
```

### Token Format

The encrypted output is a Base64-encoded JSON package containing:

| Field | Description |
|-------|-------------|
| `header` | Cipher metadata (version, algorithm identifiers) |
| `salt` | Base64-encoded 16-byte random salt |
| `iv` | Base64-encoded 32-byte random IV |
| `ciphertext` | Base64-encoded encrypted bytes |
| `tag` | Base64-encoded HMAC-SHA256 authentication tag |

Current active token version in `main_2.py`: **6**. The older `main.py` emits version **5** tokens.

---

## Authentication

HMAC-SHA256 is computed over the concatenation of:

```
header_bytes || salt || iv || ciphertext
```

using the 32-byte authentication key derived in Stage 1. This detects tampering, modification attempts, and forged ciphertexts when the Genesis Seed is unknown. Authentication is verified before any decryption occurs.

---

## Usage

### Encryption

```bash
python main_2.py
```

```
[1] Enter existing Genesis Seed
[2] Generate new random Genesis Seed

[>] Select mode 1 or 2: 2

[+] Genesis Seed: 9dc598e1de13406673664556e228a7bd89ca341818d1773f7c9442e4ef4e0061

[>] Enter a message to encrypt: Hello World

[+] ENCRYPTED TOKEN:
eyJ...
```

Save both the **Genesis Seed** and the **Encrypted Token**. Both are required for decryption.

### Decryption

```bash
python decrypt.py
```

Provide the Genesis Seed and the Encrypted Token. Decryption succeeds only if:

- The HMAC tag is valid
- The Genesis Seed is correct
- The ciphertext has not been modified

---

## Configuration & Testing

### Target Module Selection

The test suite uses a centralized routing block. To target a specific build:

```python
# In security test scripts or decrypt.py
TARGET_CIPHER_MODULE = "main_2"
```

If using a dynamic `decrypt.py` deployment, ensure `TARGET_CIPHER_MODULE` points to the exact module build that produced the encrypted token.

### Running Test Suites

```bash
# Structural avalanche, randomized prefix uniqueness, and tamper verification
python security_tests_attack.py

# N-gram prediction, position matrices, and distinguisher tests
python state_recovery_attack_test.py

# Basic and advanced smoke/security checks
python security_tests_basic.py
python security_tests_adv.py

# Ablation diagnostics
python security_test_ablation.py
```

---

## Security Properties

### Tests Passed

**Correctness**
- Encryption/decryption consistency
- Wrong seed rejection
- Tamper detection

**Statistical**
- Entropy analysis
- Chi-square analysis
- Bit balance analysis
- Serial correlation analysis

**Attack Simulations**
- Known plaintext tests
- Prefix leakage tests
- State cycle detection
- Position bias tests
- N-gram prediction attacks
- Nearby-IV avalanche attacks

### Observed Keystream Characteristics

| Metric | Observed | Ideal |
|--------|----------|-------|
| Entropy | ~7.99 bits/byte | 8.00 |
| Bit Balance | ~50% | 50% |
| Serial Correlation | ≈ 0 | 0 |
| IV Avalanche | ~50% | 50% |

### Open Research Questions

Passing statistical tests does not constitute cryptographic security. The following remain unresolved:

- State reconstruction resistance
- Differential cryptanalysis resistance
- Algebraic attack resistance
- Chosen plaintext / chosen ciphertext attack resistance
- Formal security proofs

---

## Current Research Direction

The long-term objective is to determine whether a cryptographic primitive can be built primarily from prime fields, nonlinear manifolds, and cross-coupled dynamical systems — without conventional hash-function-based diffusion layers. Active focus areas:

- State recovery attacks
- ML-based prediction attacks
- Ablation testing
- Differential analysis
- Prime-field manifold evolution research

---

## Mathematical Foundations

### Prime Fields

A prime field is a mathematical universe where all arithmetic wraps around at a prime number `p`. Under modular arithmetic, every non-zero element has a multiplicative inverse:

```
3 × 5 = 15 ≡ 1 (mod 7)   →   3⁻¹ = 5 (mod 7)
```

This property does not hold for composite moduli (e.g., `2 × ? ≡ 1 (mod 8)` has no solution). PMTC uses four large primes to ensure every state variable inhabits a well-structured, invertible algebraic environment that resists simple shortcuts.

### Nonlinear Manifolds

A manifold is a mathematical space where a point can move. PMTC's state:

```
(x, y, z, w, a, b, c, d, e, f, g, h, counter)
```

represents one point in a high-dimensional space. Each cipher step moves that point according to nonlinear rules. Operations like `pow(x, 3, p)` and `mod_inverse(...)` create nonlinear transition rules. The test suite probes whether small input changes produce large output changes, but these experiments are not a formal proof of confusion or diffusion.

### Cross-Coupled Dynamical Systems

Two subsystems that never interact can be analyzed separately. PMTC tries to avoid this by routing prime-field values directly into ARX updates, and ARX values directly into prime-field updates:

```python
a = (a + b + x) & MASK64      # prime-field x enters ARX
new_x = f(x, y, z, w, a, ...) # ARX state a enters prime field
```

The design goal is that an attacker would need to reason about both subsystems simultaneously, increasing the apparent complexity of analytical attacks.

### Physics Theoretical Visualizaiton:

Imagine your message is a tiny necklace made of atoms, each atom carrying one byte of meaning.
First, the Genesis Seed acts like the secret physical constants of a private universe. From it, the cipher derives two hidden forces: one force for scrambling motion, and one force for checking later that nobody disturbed the experiment.
Then a random salt and IV are like choosing a fresh lab chamber and initial conditions. Same message, same seed, different chamber: the atoms start in a totally different universe.
Inside that universe is the “manifold”: a high-dimensional physics arena with coordinates:
x, y, z, w, a, b, c, d, e, f, g, h, counter
Think of x, y, z, w as four particles trapped on circular prime-field tracks. Each track wraps around at a huge prime number, like a particle moving around a perfectly measured ring. The ARX variables are more like spinning gyroscopes: they rotate, collide, add momentum, and flip orientation through XOR.
For each byte-atom of your message:
The machine evolves the universe forward.
The prime-field particles jump according to nonlinear laws: cubing, fifth powers, modular inverses. Physically, it is like gravity changing direction depending on where everything already is.

The gyroscopes collide.
Addition is like momentum transfer. Rotation is like spin. XOR is like a phase flip. Every state variable nudges the others.

The cipher extracts one tiny measurement.
After the state has churned, it takes a 1-byte “sensor reading” from the whole universe. This is the keystream byte.

Your message atom meets the sensor reading.
The plaintext byte and keystream byte are XORed. That is like the atom passing through a phase mask: same size, same position in the chain, but its observable identity changes.

The resulting ciphertext atom is thrown back into the universe.
This is the fun part: the encrypted byte does not merely leave. It splashes back into the manifold and alters the future motion. So every later atom is encrypted in a universe that remembers all earlier encrypted atoms.

After the whole atomic necklace has passed through, the cipher packs up:
the lab conditions: salt and IV
the transformed atom-string: ciphertext
a description of the apparatus: header
a tamper seal: HMAC tag
Then it wraps the whole thing in Base64, like putting the experiment in a clean glass capsule.
So physically, the encrypted token is like:
A sealed record of a private miniature universe where your message-atoms were marched one by one through nonlinear prime-field gravity, spinning ARX gyroscopes, phase flips, and feedback ripples until their original arrangement became unreadable without the Genesis Seed.

---

## License

Research and educational use only. No warranty is provided regarding cryptographic security.
