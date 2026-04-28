import hashlib

def prg(master_seed: bytes) -> tuple[bytes, bytes]:
    # Create seed A by hashing with a "1"
    seed_a = hashlib.sha256(master_seed + b"1").digest()
    # Create seed B by hashing with a "2"
    seed_b = hashlib.sha256(master_seed + b"2").digest()
    return seed_a, seed_b