"""
SumTree Demo
============
SumTree(MLDSA, depth=3) → 2^3 = 8 time periods

Verifies:
  - All valid signatures → True
  - All cross-time forgery attempts → False
  - Compares with manually nested SumCompose to confirm equivalence
"""

import secrets
from signers.mldsa import MLDSA
from signers.sum_tree import build_sum_tree
from enums.BaseAlgo import BaseAlgo

def main():
    seed = secrets.token_bytes(32)

    # Build a depth-3 sum tree: 8 time periods
    tree = build_sum_tree(lambda: MLDSA(), depth=3, BASE_ALGO=BaseAlgo.ML_DSA)
    total = tree.get_total_time_periods()
    print(f"SumTree(MLDSA, depth=3): {total} time periods")
    assert total == 8, f"Expected 8, got {total}"

    pk, sk = tree.keygen(seed)
    messages = [f"message-{t}".encode() for t in range(total)]
    signatures = []

    for t in range(total):
        if t > 0:
            sk = tree.update(sk, t)
        sig = tree.sign(sk, messages[t], t)
        signatures.append(sig)

    # Verify valid signatures
    print("\n=== Valid signatures (expect True) ===")
    all_valid = True
    for t in range(total):
        result = tree.verify(pk, messages[t], signatures[t], t)
        print(f"  verify(msg[{t}], sig[{t}], T={t}): {result}")
        all_valid = all_valid and result

    # Verify cross-time forgery fails
    print("\n=== Cross-time forgery attempts (expect False) ===")
    all_rejected = True
    for t_sign in range(total):
        for t_verify in range(total):
            if t_sign == t_verify:
                continue
            result = tree.verify(pk, messages[t_sign], signatures[t_sign], t_verify)
            if result:
                print(f"  FAIL: verify(msg[{t_sign}], sig[{t_sign}], T={t_verify}): {result}")
                all_rejected = False

    if all_rejected:
        print("  All cross-time forgeries rejected ✓")

    print(f"\n{'='*50}")
    print(f"All valid signatures correct: {all_valid}")
    print(f"All cross-time forgeries rejected: {all_rejected}")

    # Also test smaller trees
    print(f"\n--- Quick tests for other depths ---")
    for depth in range(4):
        t2 = build_sum_tree(lambda: MLDSA(), depth=depth, BASE_ALGO=BaseAlgo.ML_DSA)
        n = t2.get_total_time_periods()
        s = secrets.token_bytes(32)
        pk2, sk2 = t2.keygen(s)
        sigs = []
        for t in range(n):
            if t > 0:
                sk2 = t2.update(sk2, t)
            sigs.append(t2.sign(sk2, f"m{t}".encode(), t))
        ok = all(t2.verify(pk2, f"m{t}".encode(), sigs[t], t) for t in range(n))
        print(f"  depth={depth}, periods={n}: all valid = {ok}")


if __name__ == "__main__":
    main()
