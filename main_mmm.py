"""
Full MMM Scheme Demo
====================
MMM(MLDSA, l=4) → 4 epochs, 2^4 - 1 = 15 total time periods

Epoch layout:
  Epoch 0: t=0           (1 sub-period,  B_0 depth=0)
  Epoch 1: t=1..2        (2 sub-periods, B_1 depth=1)
  Epoch 2: t=3..6        (4 sub-periods, B_2 depth=2)
  Epoch 3: t=7..14       (8 sub-periods, B_3 depth=3)

Verifies:
  - All valid signatures → True
  - All cross-time forgery attempts → False
"""

import secrets
from signers.mldsa import MLDSA
from signers.mmm import MMM, _epoch, _sub_period


def main():
    seed = secrets.token_bytes(32)

    l = 4
    mmm = MMM(lambda: MLDSA(), l=l)
    total = mmm.get_total_time_periods()
    print(f"MMM(MLDSA, l={l}): {total} time periods across {l} epochs\n")

    # Show epoch layout
    print("Epoch layout:")
    for t in range(total):
        e = _epoch(t)
        s = _sub_period(t)
        print(f"  t={t:2d} → epoch={e}, sub={s}")
    print()

    pk, sk = mmm.keygen(seed)
    messages = [f"message-{t}".encode() for t in range(total)]
    signatures = []

    # Sign at each time period
    for t in range(total):
        if t > 0:
            mmm.update(t)
        sig = mmm.sign(sk, messages[t], t)
        signatures.append(sig)
        e = _epoch(t)
        s = _sub_period(t)
        print(f"  Signed t={t:2d} (epoch={e}, sub={s})")

    # Verify valid signatures
    print("\n=== Valid signatures (expect True) ===")
    all_valid = True
    for t in range(total):
        result = mmm.verify(pk, messages[t], signatures[t], t)
        status = "✓" if result else "✗"
        print(f"  {status} verify(msg[{t:2d}], sig[{t:2d}], T={t:2d}): {result}")
        all_valid = all_valid and result

    # Verify cross-time forgery fails (sample — full matrix is 15x15=210 checks)
    print("\n=== Cross-time forgery attempts (expect False) ===")
    all_rejected = True
    fail_count = 0
    total_checks = 0
    for t_sign in range(total):
        for t_verify in range(total):
            if t_sign == t_verify:
                continue
            total_checks += 1
            result = mmm.verify(pk, messages[t_sign], signatures[t_sign], t_verify)
            if result:
                print(f"  FAIL: verify(msg[{t_sign}], sig[{t_sign}], T={t_verify}): True")
                all_rejected = False
                fail_count += 1

    if all_rejected:
        print(f"  All {total_checks} cross-time forgeries rejected ✓")
    else:
        print(f"  {fail_count}/{total_checks} forgeries incorrectly accepted!")

    print(f"\n{'='*55}")
    print(f"All valid signatures correct:      {all_valid}")
    print(f"All cross-time forgeries rejected:  {all_rejected}")

    # Quick test with smaller l
    print(f"\n--- Quick tests for other l values ---")
    for test_l in [1, 2, 3]:
        s = secrets.token_bytes(32)
        m = MMM(lambda: MLDSA(), l=test_l)
        n = m.get_total_time_periods()
        pk2, sk2 = m.keygen(s)
        sigs = []
        for t in range(n):
            if t > 0:
                m.update(t)
            sigs.append(m.sign(sk2, f"m{t}".encode(), t))
        ok = all(m.verify(pk2, f"m{t}".encode(), sigs[t], t) for t in range(n))
        print(f"  l={test_l}, epochs={test_l}, periods={n}: all valid = {ok}")


if __name__ == "__main__":
    main()
