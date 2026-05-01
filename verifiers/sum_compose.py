import hashlib
from dilithium_py.ml_dsa import ML_DSA_65

def mldsa_sum_tree_verify(pk: bytes, message: bytes, signature, t: int, T) -> bool:
    merkle_path = _get_merkle_path(t, T)
    sig_payload, pk_a, pk_b, sig_t = signature

    if sig_t != t:
        return False

    for direction in merkle_path[:len(merkle_path) - 1]:
        if hashlib.sha256(pk_a + pk_b).digest() != pk:
            return False

        pk = pk_b if direction == 'R' else pk_a

        signature = sig_payload
        sig_payload, pk_a, pk_b, sig_t = signature

    # Base verification
    direction = merkle_path[-1]
    if hashlib.sha256(pk_a + pk_b).digest() != pk:
        return False
    return ML_DSA_65.verify(pk_b if direction == 'R' else pk_a, message, sig_payload)

def _get_merkle_path(t, T) -> list[str]:
    num_bits: int = T.bit_length() - 1
    bit_str = f"{t:0{num_bits}b}"

    return ['L' if bit == '0' else 'R' for bit in bit_str]