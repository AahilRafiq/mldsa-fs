from mldsa import MLDSA
import secrets
from prg import prg

def main():
    signer = MLDSA()
    seed = secrets.token_bytes(32)
    seed_a, seed_b = prg(seed)

    pk_a, sk_a = signer.keygen(seed_a)
    message_a = b"Hello World One"
    signature_a = signer.sign(sk_a, message_a)

    pk_b, sk_b = signer.keygen(seed_b)
    message_b = b"Hello World Two"
    signature_b = signer.sign(sk_b, message_b)

    print(signer.verify(pk_a, message_a, signature_a))
    print(signer.verify(pk_b, message_b, signature_b))
    print(signer.verify(pk_a, message_b, signature_b))
    print(signer.verify(pk_b, message_a, signature_a))

if __name__ == "__main__":
    main()
