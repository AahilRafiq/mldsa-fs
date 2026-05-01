from signers.mmm import MMM, _epoch, _sub_period
import secrets


def main():
    print("=== MMM Forward-Secure Signature Scheme Demo ===\n")

    l = 2  # 2^2 = 4 epochs
    mmm = MMM(l)
    seed = secrets.token_bytes(32)
    pk, sk = mmm.keygen(seed)
    print(f"Key generated. pk = {pk.hex()[:24]}...\n")

    messages = {
        0: b"message at t=0 (epoch 0)",
        1: b"message at t=1 (epoch 1, sub 0)",
        2: b"message at t=2 (epoch 1, sub 1)",
        3: b"message at t=3 (epoch 2, sub 0)",
        4: b"message at t=4 (epoch 2, sub 1)",
    }

    signatures = {}
    sk_snapshots = {}

    for t, msg in messages.items():
        sig = mmm.sign(sk, msg, t)
        signatures[t] = sig
        sk_snapshots[t] = sk
        print(f"  Signed at t={t}  [epoch={_epoch(t)}, sub={_sub_period(t)}]  msg={msg.decode()!r}")
        next_t = t + 1
        if next_t <= max(messages):
            sk = mmm.update(sk, next_t)

    print("\n=== Valid signatures (expect all True) ===")
    for t, msg in messages.items():
        result = mmm.verify(pk, msg, signatures[t], t)
        print(f"  verify(msg[{t}], sig[{t}], t={t}): {result}")

    print("\n=== Cross-time forgery attempts (expect all False) ===")
    for t_sign, msg in messages.items():
        for t_verify in messages:
            if t_sign == t_verify:
                continue
            result = mmm.verify(pk, msg, signatures[t_sign], t_verify)
            print(f"  verify(sig_from_t={t_sign}, claimed_t={t_verify}): {result}")

    print("\n=== Forward security: compromised old sk cannot forge future signatures ===")
    # Attacker gets sk at t=1, tries to sign at t=2
    sk_leaked = sk_snapshots[1]
    forged_msg = b"forged message using old key"
    forged_sig = mmm.sign(sk_leaked, forged_msg, 2)
    result = mmm.verify(pk, forged_msg, forged_sig, 2)
    print(f"  Leaked sk at t=1, attempted forge at t=2: {result}")


if __name__ == "__main__":
    main()
