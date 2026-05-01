from signers.mldsa import MLDSA
import secrets
from signers.sum_compose import SumCompose

def main():
    seed = secrets.token_bytes(32)

    mldsa_a = MLDSA()
    mldsa_b = MLDSA()
    mldsa_c = MLDSA()
    mldsa_d = MLDSA()

    mldsa_composed = SumCompose(SumCompose(mldsa_a, mldsa_b), SumCompose(mldsa_c, mldsa_d))
    messages = [
        b"message at 0",
        b"message at 1",
        b"message at 2",
        b"message at 3",
    ]
    signatures = []
    pk, sk = mldsa_composed.keygen(seed)

    # t = 0
    sign0 = mldsa_composed.sign(sk, messages[0], 0)

    # t = 1
    sk = mldsa_composed.update(sk, 1)
    sign1 = mldsa_composed.sign(sk, messages[1], 1)

    # t = 2
    sk = mldsa_composed.update(sk, 2)
    sign2 = mldsa_composed.sign(sk, messages[2], 2)

    # t = 3
    sk = mldsa_composed.update(sk, 3)
    sign3 = mldsa_composed.sign(sk, messages[3], 3)

    signatures = [sign0, sign1, sign2, sign3]

    print("=== Valid signatures (expect True) ===")
    for t in range(4):
        result = mldsa_composed.verify(pk, messages[t], signatures[t], t)
        print(f"verify(msg[{t}], sig[{t}], T={t}): {result}")

    print("\n=== Cross-time forgery attempts (expect False) ===")
    for t_sign in range(4):
        for t_verify in range(4):
            if t_sign == t_verify:
                continue
            result = mldsa_composed.verify(pk, messages[t_sign], signatures[t_sign], t_verify)
            print(f"verify(msg[{t_sign}], sig[{t_sign}], T={t_verify}): {result}")

def main2():
    seed = secrets.token_bytes(32)

    mldsa_a = MLDSA()
    mldsa_b = MLDSA()
    mldsa_c = MLDSA()
    mldsa_d = MLDSA()

    mldsa_composed = SumCompose(SumCompose(mldsa_a, mldsa_b), SumCompose(mldsa_c, mldsa_d))

    pk, sk_0 = mldsa_composed.keygen(seed)

    message0 = b"message at 0"
    sign0 = mldsa_composed.sign(sk_0, message0, 0)

    message1 = b"message at 1"
    sk_1 = mldsa_composed.update(sk_0, 1)
    sign1 = mldsa_composed.sign(sk_1, message1, 1)

    print(f"Verify sign0 at t=0 (expect True):  {mldsa_composed.verify(pk, message0, sign0, 0)}")
    print(f"Verify sign1 at t=1 (expect True):  {mldsa_composed.verify(pk, message1, sign1, 1)}")
    print(f"Verify sign1 at t=0 (expect False): {mldsa_composed.verify(pk, message1, sign1, 0)}")
    print(f"Verify sign0 at t=1 (expect False): {mldsa_composed.verify(pk, message0, sign0, 1)}")

    # sk_0 is compromised: attacker uses it to sign at t=1 (claiming future period)
    message_forged = b"forged at t=1"
    sign_forged = mldsa_composed.sign(sk_0, message_forged, 1)
    print(f"\nCompromised sk_0 used to sign at t=1 (expect False): {mldsa_composed.verify(pk, message_forged, sign_forged, 1)}")

if __name__ == "__main__":
    main()
    main2()