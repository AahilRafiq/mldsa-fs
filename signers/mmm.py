"""
The Full MMM Scheme (Malkin-Micciancio-Miner, EUROCRYPT 2002) — Section 8

A two-level forward-secure signature scheme with effectively unbounded
time periods, built generically from any standard signature scheme.

Architecture:
  - Top-level tree L: SumTree(S, depth=log2(l)), giving l epochs
  - Bottom-level tree B_e at epoch e: SumTree(S, depth=e), giving 2^e sub-periods
  - Total periods: 2^0 + 2^1 + ... + 2^(l-1) = 2^l - 1

Time mapping:
  epoch(t)      = floor(log2(t + 1))
  sub_period(t) = t - (2^epoch(t) - 1)

Convention: update(t) prepares the scheme for signing at time t.
Called BEFORE sign(t).
"""

import math
from typing import Any, Callable

from interfaces.signature import AbstractSignature
from signers.sum_tree import build_sum_tree
from helpers.prg import prg


def _epoch(t: int) -> int:
    """epoch(t) = floor(log2(t + 1))"""
    return (t + 1).bit_length() - 1


def _sub_period(t: int) -> int:
    """sub_period(t) = t - (2^epoch(t) - 1)"""
    e = _epoch(t)
    return t - ((1 << e) - 1)


def _epoch_size(e: int) -> int:
    """Number of sub-periods in epoch e = 2^e"""
    return 1 << e


def _epoch_start(e: int) -> int:
    """Global time index where epoch e begins = 2^e - 1"""
    return (1 << e) - 1


def _pk_to_bytes(pk) -> bytes:
    if isinstance(pk, bytes):
        return pk
    return bytes(pk)


class MMM(AbstractSignature):
    """
    The MMM forward-secure signature scheme.

    Args:
        scheme_factory: callable returning a fresh base signature instance
        l: security parameter controlling max epochs (l epochs, 2^l - 1 total periods)
    """

    def __init__(self, scheme_factory: Callable[[], AbstractSignature], l: int):
        self.scheme_factory = scheme_factory
        self.l = l  # number of epochs

        # Top-level tree depth: ceil(log2(l)) to hold l leaves
        # For l that is a power of 2, this is exact; otherwise we round up
        self._top_depth = math.ceil(math.log2(l)) if l > 1 else 0

        # Build the top-level tree L (handles l epochs as time periods)
        # Note: SumTree gives 2^top_depth leaves, which is >= l
        self.L: AbstractSignature | None = None

        # Current bottom-level tree B_e
        self.B: AbstractSignature | None = None

        self.secret_state: dict[str, Any] | None = {
            'sk_L': None,
            'cert': None,
            'sk_B': None,
            'pk_B': None,
            'pk_L': None,
            'seed_chain': None,
            'current_epoch': 0,
        }

    def keygen(self, seed: bytes = None) -> tuple[Any, Any]:
        """
        1. Split seed → (seed_top, seed_chain)
        2. Build top-level SumTree L from seed_top
        3. Derive B_0 = SumTree(S, depth=0) from seed_chain
        4. L certifies B_0's public key at epoch 0
        5. Advance L to epoch 1
        """
        seed_top, seed_chain = prg(seed)
        seed_B0, seed_chain_next = prg(seed_chain)

        # Build top-level tree
        self.L = build_sum_tree(self.scheme_factory, self._top_depth)
        pk_L, sk_L = self.L.keygen(seed_top)

        # Build epoch 0's bottom tree: depth=0 → single base instance
        self.B = build_sum_tree(self.scheme_factory, 0)
        pk_B0, sk_B0 = self.B.keygen(seed_B0)

        # L certifies B_0 at epoch 0
        cert_0 = self.L.sign(sk_L, _pk_to_bytes(pk_B0), 0)

        # Advance L to be ready for epoch 1
        if self.l > 1:
            self.L.update(1)

        self.secret_state['sk_L'] = sk_L
        self.secret_state['cert'] = cert_0
        self.secret_state['sk_B'] = sk_B0
        self.secret_state['pk_B'] = pk_B0
        self.secret_state['pk_L'] = pk_L
        self.secret_state['seed_chain'] = seed_chain_next
        self.secret_state['current_epoch'] = 0

        return pk_L, sk_L

    def sign(self, sk, message: bytes, t: int) -> tuple:
        """
        Sign message at global time t.
        Returns (pk_B, cert, sig_B, t).
        """
        s = _sub_period(t)

        sig_B = self.B.sign(self.secret_state['sk_B'], message, s)

        return (
            self.secret_state['pk_B'],
            self.secret_state['cert'],
            sig_B,
            t,
        )

    def verify(self, pk, message: bytes, signature, t: int) -> bool:
        """
        Verify signature at global time t.
        1. Check L certified pk_B at epoch(t)
        2. Check B signed message at sub_period(t)
        """
        pk_B, cert, sig_B, sig_t = signature

        if sig_t != t:
            return False

        e = _epoch(t)
        s = _sub_period(t)

        # Step 1: verify L certified this bottom tree for this epoch
        if not self.L.verify(pk, _pk_to_bytes(pk_B), cert, e):
            return False

        # Step 2: verify B signed the message at this sub-period
        # We need a B tree of the right depth for verification
        # The B instance used for signing may have evolved, but verify is
        # stateless — it only depends on the tree structure (depth=e)
        # and the signature carries all the path info.
        # Since SumCompose.verify is stateless (uses T_A for routing and
        # delegates to base scheme verify), we can build a fresh tree.
        B_verify = build_sum_tree(self.scheme_factory, e)
        if not B_verify.verify(pk_B, message, sig_B, s):
            return False

        return True

    def update(self, t: int):
        """
        Prepare for signing at global time t.

        If t is in the same epoch: advance B to the new sub-period.
        If t starts a new epoch: build fresh B, certify with L, advance L.
        """
        new_epoch = _epoch(t)
        new_sub = _sub_period(t)
        cur_epoch = self.secret_state['current_epoch']

        if new_epoch == cur_epoch:
            # Same epoch — advance B within the epoch
            self.B.update(new_sub)
        else:
            # Epoch transition — build new bottom tree
            seed_B_new, seed_chain_next = prg(self.secret_state['seed_chain'])

            # B_{new_epoch} = SumTree(S, depth=new_epoch)
            self.B = build_sum_tree(self.scheme_factory, new_epoch)
            pk_B_new, sk_B_new = self.B.keygen(seed_B_new)

            # L certifies the new bottom tree at new_epoch
            cert_new = self.L.sign(
                self.secret_state['sk_L'],
                _pk_to_bytes(pk_B_new),
                new_epoch,
            )

            # Advance L past new_epoch
            next_L_epoch = new_epoch + 1
            if next_L_epoch < self.l:
                self.L.update(next_L_epoch)

            # Replace state
            self.secret_state['sk_B'] = sk_B_new
            self.secret_state['pk_B'] = pk_B_new
            self.secret_state['cert'] = cert_new
            self.secret_state['seed_chain'] = seed_chain_next
            self.secret_state['current_epoch'] = new_epoch

    def get_total_time_periods(self) -> int:
        """Total = 2^0 + 2^1 + ... + 2^(l-1) = 2^l - 1"""
        return (1 << self.l) - 1

    def p_keygen(self, seed: bytes = None) -> bytes:
        seed_top, _ = prg(seed)
        L_temp = build_sum_tree(self.scheme_factory, self._top_depth)
        pk, _ = L_temp.keygen(seed_top)
        return _pk_to_bytes(pk)

    def s_keygen(self, seed: bytes = None) -> bytes:
        _, sk = self.keygen(seed)
        return sk

    def cleanup(self):
        self.secret_state = None
        if self.L:
            self.L.cleanup()
        if self.B:
            self.B.cleanup()
