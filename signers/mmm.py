from typing import Any

from helpers.prg import prg
from interfaces.signature import AbstractSignature
from signers.sum_tree import build_sum_tree
from signers.mldsa import MLDSA
from verifiers.sum_compose import mldsa_sum_tree_verify

def _epoch(t: int) -> int:
    """epoch(t) = floor(log2(t + 1))"""
    return (t + 1).bit_length() - 1

def _sub_period(t: int) -> int:
    """sub_period(t) = t - (2^epoch(t) - 1)"""
    e = _epoch(t)
    return t - ((1 << e) - 1)


class MMM(AbstractSignature):

    def __init__(self, l: int):
        self.main_tree:AbstractSignature = build_sum_tree(lambda: MLDSA(), l)
        self.epoch_tree:AbstractSignature = build_sum_tree(lambda: MLDSA(), 0)
        self.T_main = pow(2, l)
        self.T_B = 1

    def get_total_time_periods(self) -> int:
        return self.main_tree.get_total_time_periods()

    def keygen(self, seed: bytes = None) -> tuple[Any, Any]:
        seed_main, seed_chain = prg(seed)
        secret_state = {}

        pk_main, sk_main = self.main_tree.keygen(seed_main)
        secret_state['sk_main'] = sk_main
        secret_state['pk_main'] = pk_main

        seed_B0, seed_chain_new = prg(seed_chain)
        pk_B0, sk_B0 = self.epoch_tree.keygen(seed_B0)
        cert = self.main_tree.sign(sk_main, pk_B0, 0)

        secret_state['cert'] = cert
        secret_state['pk_B'] = pk_B0
        secret_state['seed_chain'] = seed_chain_new
        secret_state['curr_epoch'] = 0

        return pk_main, secret_state

    def sign(self, sk, message: bytes, t: int):
        sub_period = _sub_period(t)

        sign = self.epoch_tree.sign(sk['pk_B'], message, sub_period)

        return sk['pk_B'], sk['cert'], sign, t

    def update(self, sk, t: int):
        epoch = _epoch(t)
        sub_period = _sub_period(t)

        if sk['curr_epoch'] == epoch:
            sk['sk_main'] = self.epoch_tree.update(sk['sk_main'], sub_period)
        else:
            sk['sk_main'] = self.main_tree.update(sk['sk_main'], epoch)
            sk['curr_epoch'] = epoch

            seed_B_new, seed_chain_new = prg(sk['seed_chain'])
            self.epoch_tree = build_sum_tree(lambda: MLDSA(), epoch)
            sk_B_new, pk_B_new = self.epoch_tree.keygen(seed_B_new)
            cert_new = self.main_tree.sign(sk['sk_main'], pk_B_new, epoch)

            sk['cert'] = cert_new
            sk['pk_B'] = pk_B_new
            sk['seed_chain'] = seed_chain_new

        return sk

    def verify(self, pk, message, signature, t: int):
        epoch = _epoch(t)
        sub_period = _sub_period(t)

        pk_B, cert, sign, t = signature

        if not self.main_tree.verify(pk, pk_B, cert, epoch):
            return False

        if not mldsa_sum_tree_verify(pk_B, message, signature, sub_period, (1 << epoch)):
            return False

        return True

    def p_keygen(self, seed: bytes = None) -> tuple[Any, Any]:
        pass

    def s_keygen(self, seed: bytes = None) -> tuple[Any, Any]:
        pass

    def cleanup(self):
        pass