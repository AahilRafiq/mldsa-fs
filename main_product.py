"""
Product Composition Demo
========================
Product(A, B) where:
  - A = SumCompose(MLDSA, MLDSA)  → 2 epochs
  - B = SumCompose(MLDSA, MLDSA)  → 2 sub-periods per epoch

Total: 2 * 2 = 4 time periods

Expected output:
  - Valid signatures (same t) → True
  - Cross-time forgery (different t) → False
"""

import secrets
from signers.mldsa import MLDSA
from signers.sum_compose import SumCompose
from signers.product_compose import ProductCompose


def main():
    seed = secrets.token_bytes(32)

    # Outer scheme A: 2 epochs via Sum(MLDSA, MLDSA)
    scheme_A = SumCompose(MLDSA(), MLDSA())

    # Inner scheme B: 2 sub-periods per epoch via Sum(MLDSA, MLDSA)
    scheme_B = SumCompose(MLDSA(), MLDSA())

    product = ProductCompose(scheme_A, scheme_B)

    total = product.get_total_time_periods()
    print(f"Product composition: {product.T_A} epochs × {product.T_B} sub-periods = {total} time periods\n")

    pk, sk = product.keygen(seed)

    messages = [f"message at {t}".encode() for t in range(total)]
    signatures = []

    # Sign at each time period, calling update(sk, t) BEFORE sign(t)
    for t in range(total):
        if t > 0:
            product.update(sk, t)
        sig = product.sign(sk, messages[t], t)
        signatures.append(sig)

    # --- Verification ---

    print("=== Valid signatures (expect True) ===")
    for t in range(total):
        result = product.verify(pk, messages[t], signatures[t], t)
        print(f"  verify(msg[{t}], sig[{t}], T={t}): {result}")

    print("\n=== Cross-time forgery attempts (expect False) ===")
    for t_sign in range(total):
        for t_verify in range(total):
            if t_sign == t_verify:
                continue
            result = product.verify(pk, messages[t_sign], signatures[t_sign], t_verify)
            print(f"  verify(msg[{t_sign}], sig[{t_sign}], T={t_verify}): {result}")

    # --- Summary ---
    valid_ok = all(
        product.verify(pk, messages[t], signatures[t], t)
        for t in range(total)
    )
    forge_ok = all(
        not product.verify(pk, messages[ts], signatures[ts], tv)
        for ts in range(total) for tv in range(total) if ts != tv
    )
    print(f"\nAll valid signatures correct: {valid_ok}")
    print(f"All cross-time forgeries rejected: {forge_ok}")


if __name__ == "__main__":
    main()
