from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

_PARAM_SETS = {
    "ML-DSA-44": ML_DSA_44,
    "ML-DSA-65": ML_DSA_65,
    "ML-DSA-87": ML_DSA_87,
}

class MLDSA:
    def __init__(self, param_set: str = "ML-DSA-65"):
        if param_set not in _PARAM_SETS:
            raise ValueError(f"param_set must be one of {list(_PARAM_SETS)}")
        self.ml_dsa = _PARAM_SETS[param_set]

    def keygen(self, seed: bytes=None) -> tuple[bytes, bytes]:
        """Generate a (pk, sk) key pair using seed."""
        if seed is None:
            return self.ml_dsa.keygen()
        return self.ml_dsa.key_derive(seed)

    def sign(self, sk: bytes, message: bytes, ctx: bytes = b"") -> bytes:
        """Returns the signature 32 bytes."""
        return self.ml_dsa.sign(sk, message, ctx)

    def verify(self, pk: bytes, message: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        return self.ml_dsa.verify(pk, message, sig, ctx)

    def p_keygen(self, seed: bytes) -> bytes:
        """Derive the public key from seed."""
        pk, sk = self.ml_dsa.key_derive(seed)
        return pk

    def s_keygen(self, seed: bytes) -> tuple[bytes, bytes]:
        pass