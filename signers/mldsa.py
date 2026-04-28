from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from interfaces.signature import AbstractSignature

_PARAM_SETS = {
    "ML-DSA-44": ML_DSA_44,
    "ML-DSA-65": ML_DSA_65,
    "ML-DSA-87": ML_DSA_87,
}

class MLDSA(AbstractSignature):
    def __init__(self, param_set: str = "ML-DSA-65"):
        if param_set not in _PARAM_SETS:
            raise ValueError(f"param_set must be one of {list(_PARAM_SETS)}")
        self.ml_dsa = _PARAM_SETS[param_set]

    def keygen(self, seed: bytes = None) -> tuple[bytes, bytes]:
        if seed is None:
            return self.ml_dsa.keygen()
        return self.ml_dsa.key_derive(seed)

    def sign(self, sk: bytes, message: bytes, t: int = 0) -> bytes:
        return self.ml_dsa.sign(sk, message)

    def verify(self, pk: bytes, message: bytes, signature: bytes, t: int = 0) -> bool:
        return self.ml_dsa.verify(pk, message, signature)

    def p_keygen(self, seed: bytes = None) -> bytes:
        pk, _ = self.ml_dsa.key_derive(seed)
        return pk

    def s_keygen(self, seed: bytes = None) -> bytes:
        _, sk = self.ml_dsa.key_derive(seed)
        return sk

    def get_total_time_periods(self) -> int:
        return 1

    def update(self, t: int) -> None:
        pass

    def cleanup(self) -> None:
        pass