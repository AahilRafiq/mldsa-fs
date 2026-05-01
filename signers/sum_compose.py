from typing import Any
from interfaces.signature import AbstractSignature
from helpers.prg import prg
from verifiers.sum_compose import mldsa_sum_tree_verify
from enums.BaseAlgo import BaseAlgo
import hashlib

class SumCompose(AbstractSignature):
    def __init__(self, scheme_A, scheme_B, BASE_ALGO = BaseAlgo.ML_DSA):
        self.scheme_A: AbstractSignature | None = scheme_A
        self.scheme_B: AbstractSignature | None = scheme_B
        self.T_A: int = scheme_A.get_total_time_periods()
        self.T_B: int = scheme_B.get_total_time_periods()
        self.BASE_ALGO: BaseAlgo = BASE_ALGO

    def keygen(self, seed: bytes = None) -> tuple[Any, Any]:
        seed_a, seed_b = prg(seed)

        pk_a, sk_a = self.scheme_A.keygen(seed_a)
        pk_b = self.scheme_B.p_keygen(seed_b)
        combined_pk = hashlib.sha256(pk_a + pk_b).digest()

        sk = {
            'active_sk': sk_a,
            'deferred_seed': seed_b,
            'pk_a': pk_a,
            'pk_b': pk_b,
        }

        return combined_pk, sk

    def update(self, sk: dict, t: int) -> dict:
        if t < self.T_A:
            new_active_sk = self.scheme_A.update(sk['active_sk'], t)
            return {
                'active_sk': new_active_sk,
                'deferred_seed': sk['deferred_seed'],
                'pk_a': sk['pk_a'],
                'pk_b': sk['pk_b'],
            }
        elif t == self.T_A:
            self.scheme_A.cleanup()
            new_active_sk = self.scheme_B.s_keygen(sk['deferred_seed'])
            return {
                'active_sk': new_active_sk,
                'deferred_seed': None,
                'pk_a': sk['pk_a'],
                'pk_b': sk['pk_b'],
            }
        else:
            new_active_sk = self.scheme_B.update(sk['active_sk'], t - self.T_A)
            return {
                'active_sk': new_active_sk,
                'deferred_seed': None,
                'pk_a': sk['pk_a'],
                'pk_b': sk['pk_b'],
            }


    def sign(self, sk, message: bytes, t: int) -> tuple:
        if t < self.T_A:
            sig_payload = self.scheme_A.sign(sk['active_sk'], message, t)
        else:
            sig_payload = self.scheme_B.sign(sk['active_sk'], message, t - self.T_A)

        return sig_payload, sk['pk_a'], sk['pk_b'], t

    def _verify(self, pk: bytes, message: bytes, signature, t: int) -> bool:
        sig_payload, pk_a, pk_b, sig_t = signature

        if sig_t != t:
            return False

        if hashlib.sha256(pk_a + pk_b).digest() != pk:
            return False

        if sig_t < self.T_A:
            return self.scheme_A.verify(pk_a, message, sig_payload, sig_t)
        else:
            return self.scheme_B.verify(pk_b, message, sig_payload, sig_t - self.T_A)

    def verify(self, pk: bytes, message: bytes, signature, t: int) -> bool:
        if self.BASE_ALGO == BaseAlgo.ML_DSA:
            return mldsa_sum_tree_verify(pk, message, signature, t, self.T_A, self.T_B)
        return self._verify(pk, message, signature, t)

    def get_total_time_periods(self) -> int:
        return self.T_A + self.scheme_B.get_total_time_periods()

    def p_keygen(self, seed: bytes = None) -> bytes:
        seed_a, seed_b = prg(seed)
        pk_a = self.scheme_A.p_keygen(seed_a)
        pk_b = self.scheme_B.p_keygen(seed_b)
        return hashlib.sha256(pk_a + pk_b).digest()

    def s_keygen(self, seed: bytes = None) -> dict:
        _, sk = self.keygen(seed)
        return sk

    def cleanup(self):
        self.scheme_A = None
        self.scheme_B = None

    def _get_merkle_path(self, t) -> list[str]:
        num_bits: int = (self.T_A + self.T_B // 2).bit_length()
        bit_str = f"{t:0{num_bits}b}"

        return ['L' if bit == '0' else 'R' for bit in bit_str]