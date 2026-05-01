

def verify(self, pk, message: bytes, signature, t: int) -> bool:
    pk_B, cert, sig_B, sig_t = signature

    if sig_t != t:
        return False