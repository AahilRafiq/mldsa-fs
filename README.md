# mldsa-fs — Forward-Secure Signatures over ML-DSA

A Python implementation of the **MMM forward-secure signature scheme**, built on top of [ML-DSA (CRYSTALS-Dilithium)](https://pq-crystals.org/dilithium/) via the `dilithium-py` library.

Forward security means that if a signer's secret key is compromised at time `t`, an attacker cannot forge valid signatures for any past time period `t' < t`.

---

## Module Structure

```
mldsa-fs/
├── interfaces/
│   └── signature.py          # Abstract signature interface
├── enums/
│   └── BaseAlgo.py           # Base algorithm enumeration
├── helpers/
│   └── prg.py                # Pseudo-Random Generator
├── signers/
│   ├── mldsa.py              # ML-DSA wrapper
│   ├── sum_compose.py        # Sum composition (binary tree node)
│   ├── sum_tree.py           # Tree builder (recursive)
│   └── mmm.py                # Main MMM scheme
└── verifiers/
    └── sum_compose.py        # Optimized verification
```

## Class Hierarchy

```
AbstractSignature (Interface)
│
├── MLDSA                 # Leaf-level base signature
│
├── SumCompose            # Binary tree composition
│
└── MMM                   # Top-level forward-secure scheme
```

## How the MMM scheme works

MMM organises time into a two-level hierarchy:

```
main_tree  (depth l, gives 2^l epochs)
  └─ epoch_tree  (depth = current epoch, rebuilt on each epoch change)
```

**Time mapping**

Every global time period `t` maps to an epoch and a sub-period within that epoch:

```
epoch(t)      = floor(log2(t + 1))
sub_period(t) = t - (2^epoch(t) - 1)
```

| t | epoch | sub |
|---|-------|-----|
| 0 |   0   |  0  |
| 1 |   1   |  0  |
| 2 |   1   |  1  |
| 3 |   2   |  0  |
| 4 |   2   |  1  |
| 5 |   2   |  2  |
| 6 |   2   |  3  |

**Key structure**

- `pk` — the main public key (a Merkle hash over the main tree, never changes)
- `sk` — a dict containing:
  - `sk_main` — current state of the main tree secret key
  - `pk_main` — main public key (stored for cert generation)
  - `sk_B` / `pk_B` — secret/public key of the current epoch tree
  - `cert` — a signature by `sk_main` over `pk_B`, binding the epoch key to the main key
  - `seed_chain` — PRG seed used to derive future epoch keys without storing them
  - `curr_epoch` — the active epoch index

**Signature structure**

Each signature is a 4-tuple `(pk_B, cert, sign, t)`:
- `pk_B` — epoch public key
- `cert` — main-tree signature certifying `pk_B` for this epoch
- `sign` — epoch-tree signature over the message at sub-period `sub_period(t)`
- `t` — the global time period

**Verification** checks:
1. `cert` is a valid main-tree signature of `pk_B` at `epoch(t)` under `pk`
2. `sign` is a valid epoch-tree signature of the message at `sub_period(t)` under `pk_B`

**Key update** (call before signing at time `t`):
- Same epoch → forward the epoch tree's secret key to the next sub-period
- New epoch → advance the main tree, derive a fresh epoch key from `seed_chain`, issue a new cert

Once updated, the old secret key material is discarded, so past periods cannot be re-signed.

---

## Usage

```python
import secrets
from signers.mmm import MMM

# Instantiate with depth l (supports 2^l epochs)
mmm = MMM(l=2)

# Key generation (optionally pass a 32-byte seed for determinism)
pk, sk = mmm.keygen(secrets.token_bytes(32))

# Sign at time t=0
msg = b"hello"
sig = mmm.sign(sk, msg, t=0)

# Advance secret key to t=1 before signing at t=1
sk = mmm.update(sk, t=1)
sig1 = mmm.sign(sk, b"next message", t=1)

# Verify — only the matching (msg, sig, t) triple verifies
assert mmm.verify(pk, msg, sig, t=0) is True
assert mmm.verify(pk, b"wrong", sig, t=0) is False
assert mmm.verify(pk, msg, sig, t=1) is False   # replay rejected
```

### Interface (`AbstractSignature`)

| Method | Signature | Description |
|--------|-----------|-------------|
| `keygen` | `(seed?) → (pk, sk)` | Generate a key pair. Pass a 32-byte seed for deterministic output. |
| `sign` | `(sk, message, t) → signature` | Sign `message` at time period `t`. |
| `verify` | `(pk, message, signature, t) → bool` | Verify a signature. Returns `False` on any mismatch. |
| `update` | `(sk, t) → sk` | Advance the secret key to time `t`. Call before `sign(t)` for all `t > 0`. |

---

## Running the demo

```bash
uv run python main.py
```

## Running the tests

```bash
./run_tests.sh
# or
uv run pytest tests/test_mmm.py -v -s
```

---

## Dependencies

- Python ≥ 3.14
- [`dilithium-py`](https://github.com/GiacomoPope/dilithium-py) — pure-Python ML-DSA implementation
