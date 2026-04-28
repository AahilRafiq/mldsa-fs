from typing import Any
from interfaces.signature import AbstractSignature
from helpers.prg import prg
import hashlib

class SumCompose(AbstractSignature):
    def __init__(self, mldsa_A, mldsa_B):
        self.mldsa_A: AbstractSignature | None = mldsa_A
        self.mldsa_B: AbstractSignature | None = mldsa_B
        self.T_A: int | None = mldsa_A.get_total_time_periods()
        self.secret_state: dict[str, Any] | None = {
            'active_sk': None,
            'deferred_seed': None,
            'pk_a': None,
            'pk_b': None
        }

    def keygen(self, seed: bytes = None) -> tuple[Any, Any]:
        seed_a, seed_b = prg(seed)

        pk_a, sk_a = self.mldsa_A.keygen(seed_a)
        pk_b = self.mldsa_B.p_keygen(seed_b)
        combined_pk = hashlib.sha256(pk_a + pk_b).digest()

        self.secret_state['pk_a'] = pk_a
        self.secret_state['pk_b'] = pk_b
        self.secret_state['active_sk'] = sk_a
        self.secret_state['deferred_seed'] = seed_b

        return combined_pk, sk_a

    def update(self, t: int):
        if t < self.T_A:
            self.mldsa_A.update(t)
        elif t == self.T_A:
            self.secret_state['active_sk'] = self.mldsa_B.s_keygen(self.secret_state['deferred_seed'])
            self.secret_state['deferred_seed'] = None
            self.mldsa_A.cleanup()
        else:
            self.mldsa_B.update(t - self.T_A)

    def sign(self, sk, message: bytes, t: int) -> tuple:
        if t < self.T_A:
            sig_payload = self.mldsa_A.sign(self.secret_state['active_sk'], message, t)
        else:
            sig_payload = self.mldsa_B.sign(self.secret_state['active_sk'], message, t - self.T_A)

        return sig_payload, self.secret_state['pk_a'], self.secret_state['pk_b'], t

    def verify(self, pk: bytes, message: bytes, signature, t: int) -> bool:
        sig_payload, pk_a, pk_b, sig_t = signature

        if sig_t != t:
            return False

        if hashlib.sha256(pk_a + pk_b).digest() != pk:
            return False

        if sig_t < self.T_A:
            return self.mldsa_A.verify(pk_a, message, sig_payload, sig_t)
        else:
            return self.mldsa_B.verify(pk_b, message, sig_payload, sig_t - self.T_A)

    def get_total_time_periods(self) -> int:
        return self.T_A + self.mldsa_B.get_total_time_periods()

    def p_keygen(self, seed: bytes = None) -> bytes:
        seed_a, seed_b = prg(seed)
        pk_a = self.mldsa_A.p_keygen(seed_a)
        pk_b = self.mldsa_B.p_keygen(seed_b)
        return hashlib.sha256(pk_a + pk_b).digest()

    def s_keygen(self, seed: bytes = None) -> bytes:
        _, sk = self.keygen(seed)
        return sk

    def cleanup(self):
        """
        Probably good enough, cleans up the state but not the object itself as the methods might always be in use
        """
        self.secret_state = None