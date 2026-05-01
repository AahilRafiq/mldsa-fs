from typing import Any
from interfaces.signature import AbstractSignature
from helpers.prg import prg


class ProductCompose(AbstractSignature):
    """
    Product composition (MMM Section 6).

    Given:
      - Scheme A with T_A time periods  (outer / epoch scheme)
      - Scheme B with T_B time periods  (inner / sub-period scheme)

    Produces a forward-secure scheme with T_A * T_B total time periods.

    Time is divided into T_A epochs, each containing T_B sub-periods:
        epoch      = t // T_B
        sub_period = t %  T_B

    Convention: update(t) prepares the scheme for signing at time t.
    It is called BEFORE sign(t).
    """

    def __init__(self, scheme_A: AbstractSignature, scheme_B: AbstractSignature):
        self.scheme_A: AbstractSignature = scheme_A
        self.scheme_B: AbstractSignature = scheme_B
        self.T_A: int = scheme_A.get_total_time_periods()
        self.T_B: int = scheme_B.get_total_time_periods()

        self.secret_state: dict[str, Any] | None = {
            'sk_A': None,
            'cert': None,
            'sk_B': None,
            'pk_B': None,
            'pk_A': None,
            'seed_chain': None,
            'current_epoch': 0,
        }

    # ------------------------------------------------------------------ #
    #  Key generation
    # ------------------------------------------------------------------ #

    def keygen(self, seed: bytes = None) -> tuple[Any, Any]:
        seed_A, seed_chain = prg(seed)
        seed_B_0, seed_chain_next = prg(seed_chain)

        pk_A, sk_A = self.scheme_A.keygen(seed_A)
        pk_B_0, sk_B_0 = self.scheme_B.keygen(seed_B_0)

        # A certifies B_0's public key at epoch 0
        cert_0 = self.scheme_A.sign(sk_A, _pk_to_bytes(pk_B_0), 0)

        # Advance A to be ready for epoch 1
        # (update(1) means "prepare for time period 1")
        self.scheme_A.update(1)

        self.secret_state['sk_A'] = sk_A
        self.secret_state['cert'] = cert_0
        self.secret_state['sk_B'] = sk_B_0
        self.secret_state['pk_B'] = pk_B_0
        self.secret_state['pk_A'] = pk_A
        self.secret_state['seed_chain'] = seed_chain_next
        self.secret_state['current_epoch'] = 0

        return pk_A, sk_A

    # ------------------------------------------------------------------ #
    #  Signing
    # ------------------------------------------------------------------ #

    def sign(self, sk, message: bytes, t: int) -> tuple:
        sub_period = t % self.T_B

        sig_B = self.scheme_B.sign(
            self.secret_state['sk_B'], message, sub_period
        )

        return (
            self.secret_state['pk_B'],
            self.secret_state['cert'],
            sig_B,
            t,
        )

    # ------------------------------------------------------------------ #
    #  Verification
    # ------------------------------------------------------------------ #

    def verify(self, pk, message: bytes, signature, t: int) -> bool:
        pk_B, cert, sig_B, sig_t = signature

        if sig_t != t:
            return False

        epoch = t // self.T_B
        sub_period = t % self.T_B

        # Step 1: verify A certified this B instance for this epoch
        if not self.scheme_A.verify(pk, _pk_to_bytes(pk_B), cert, epoch):
            return False

        # Step 2: verify B signed the message at this sub-period
        if not self.scheme_B.verify(pk_B, message, sig_B, sub_period):
            return False

        return True

    def verify(self, pk, message: bytes, signature, t: int) -> bool:
        pk_B, cert, sig_B, sig_t = signature

        if sig_t != t:
            return False

    # ------------------------------------------------------------------ #
    #  Key update / evolution
    # ------------------------------------------------------------------ #

    def update(self, t: int):
        """
        update(t) — prepare the scheme for signing at global time t.
        Called BEFORE sign(t).

        If t is in the same epoch as current: update B for the new sub-period.
        If t starts a new epoch: transition to the new epoch.
        """
        new_epoch = t // self.T_B
        new_sub = t % self.T_B
        cur_epoch = self.secret_state['current_epoch']

        if new_epoch == cur_epoch:
            # Same epoch — just advance B to the new sub-period
            self.scheme_B.update(new_sub)
        else:
            # New epoch — generate fresh B, certify with A
            seed_B_new, seed_chain_next = prg(self.secret_state['seed_chain'])
            pk_B_new, sk_B_new = self.scheme_B.keygen(seed_B_new)

            # A certifies the new B at new_epoch
            cert_new = self.scheme_A.sign(
                self.secret_state['sk_A'], _pk_to_bytes(pk_B_new), new_epoch
            )

            # Advance A past new_epoch (prepare for new_epoch + 1)
            next_a_epoch = new_epoch + 1
            if next_a_epoch < self.T_A:
                self.scheme_A.update(next_a_epoch)

            # Replace B state
            self.secret_state['sk_B'] = sk_B_new
            self.secret_state['pk_B'] = pk_B_new
            self.secret_state['cert'] = cert_new
            self.secret_state['seed_chain'] = seed_chain_next
            self.secret_state['current_epoch'] = new_epoch

    # ------------------------------------------------------------------ #
    #  Helpers required by AbstractSignature
    # ------------------------------------------------------------------ #

    def get_total_time_periods(self) -> int:
        return self.T_A * self.T_B

    def p_keygen(self, seed: bytes = None) -> bytes:
        seed_A, _ = prg(seed)
        return self.scheme_A.p_keygen(seed_A)

    def s_keygen(self, seed: bytes = None) -> bytes:
        _, sk = self.keygen(seed)
        return sk

    def cleanup(self):
        self.secret_state = None
        self.scheme_A.cleanup()
        self.scheme_B.cleanup()


def _pk_to_bytes(pk) -> bytes:
    if isinstance(pk, bytes):
        return pk
    return bytes(pk)
