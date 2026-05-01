import secrets
from signers.mmm import MMM, _epoch, _sub_period


def main():
    print("=== MMM Forward-Secure Signature Scheme Demo ===\n")

    # Instantiate MMM with depth l=2 (supports 4 main epochs)
    l = 2
    mmm = MMM(l)
    seed = secrets.token_bytes(32)

    # Key generation
    pk, sk = mmm.keygen(seed)
    print(f"Key generation complete. Public key: {pk.hex()[:32]}...")
    print(f"Initial epoch: {sk['curr_epoch']}\n")

    # Sign and verify across several time periods
    time_periods = [0, 1, 2, 3, 4, 5, 6]
    signatures = {}

    print("--- Signing ---")
    for t in time_periods:
        msg = f"message at t={t}".encode()
        if t > 0:
            sk = mmm.update(sk, t)
        sig = mmm.sign(sk, msg, t)
        signatures[t] = (msg, sig)
        print(f"  t={t}  epoch={_epoch(t)}  sub={_sub_period(t)}  msg={msg.decode()!r}")

    print("\n--- Verification (valid signatures, expect True) ---")
    for t in time_periods:
        msg, sig = signatures[t]
        result = mmm.verify(pk, msg, sig, t)
        print(f"  verify(t={t}): {result}")

    print("\n--- Cross-time replay attacks (expect False) ---")
    for t_sign in [0, 1, 3]:
        for t_verify in [1, 3, 6]:
            if t_sign == t_verify:
                continue
            msg, sig = signatures[t_sign]
            result = mmm.verify(pk, msg, sig, t_verify)
            print(f"  sig from t={t_sign} replayed at t={t_verify}: {result}")

    print("\n--- Tampered message (expect False) ---")
    msg, sig = signatures[0]
    result = mmm.verify(pk, b"tampered message", sig, 0)
    print(f"  verify(tampered_msg, sig_t0, t=0): {result}")

    print("\n--- Wrong public key (expect False) ---")
    wrong_pk, _ = MMM(l).keygen(secrets.token_bytes(32))
    msg, sig = signatures[0]
    result = mmm.verify(wrong_pk, msg, sig, 0)
    print(f"  verify(wrong_pk, msg, sig_t0, t=0): {result}")


if __name__ == "__main__":
    main()
