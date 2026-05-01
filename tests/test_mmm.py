"""
Tests for the MMM forward-secure signature scheme.

MMM constructs two levels:
  - main_tree: SumTree of depth l, giving 2^l epochs
  - epoch_tree: a SumTree of depth `epoch`, rebuilt each time the epoch changes

Time mapping:
  epoch(t)      = floor(log2(t + 1))
  sub_period(t) = t - (2^epoch(t) - 1)

Example for l=2 (T_main=4 epochs):
  t=0 -> epoch=0, sub=0
  t=1 -> epoch=1, sub=0
  t=2 -> epoch=1, sub=1
  t=3 -> epoch=2, sub=0
  t=4 -> epoch=2, sub=1
  t=5 -> epoch=2, sub=2
  t=6 -> epoch=2, sub=3
"""
import copy
import secrets

import pytest

from signers.mmm import MMM, _epoch, _sub_period


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def full_lifecycle(l: int):
    """
    Returns (mmm, pk, list_of_(sk_snapshot, msg, sig, t)) for every t in
    0 .. (first 3 epochs worth of periods), advancing sk between each step.
    """
    mmm = MMM(l)
    seed = secrets.token_bytes(32)
    pk, sk = mmm.keygen(seed)

    results = []
    t = 0
    for _ in range(min(7, 2 ** l + 3)):
        msg = f"message at t={t}".encode()
        sig = mmm.sign(sk, msg, t)
        results.append((copy.deepcopy(sk), msg, sig, t))
        t += 1
        sk = mmm.update(sk, t)
    return mmm, pk, results


# ---------------------------------------------------------------------------
# Utility / helper function tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_epoch_t0(self, capsys):
        print("\n[TestHelpers] Testing epoch(0) == 0")
        assert _epoch(0) == 0
        print("  PASS: epoch(0) = 0")

    def test_epoch_t1(self, capsys):
        print("\n[TestHelpers] Testing epoch(1) == 1")
        assert _epoch(1) == 1
        print("  PASS: epoch(1) = 1")

    def test_epoch_t2(self, capsys):
        print("\n[TestHelpers] Testing epoch(2) == 1  (t=2 is still epoch 1)")
        assert _epoch(2) == 1
        print("  PASS: epoch(2) = 1")

    def test_epoch_t3(self, capsys):
        print("\n[TestHelpers] Testing epoch(3) == 2  (first t of epoch 2)")
        assert _epoch(3) == 2
        print("  PASS: epoch(3) = 2")

    def test_epoch_t6(self, capsys):
        print("\n[TestHelpers] Testing epoch(6) == 2")
        assert _epoch(6) == 2
        print("  PASS: epoch(6) = 2")

    def test_epoch_t7(self, capsys):
        print("\n[TestHelpers] Testing epoch(7) == 3  (first t of epoch 3)")
        assert _epoch(7) == 3
        print("  PASS: epoch(7) = 3")

    def test_sub_period_t0(self, capsys):
        print("\n[TestHelpers] Testing sub_period(0) == 0")
        assert _sub_period(0) == 0
        print("  PASS: sub_period(0) = 0")

    def test_sub_period_t1(self, capsys):
        print("\n[TestHelpers] Testing sub_period(1) == 0  (first sub-period of epoch 1)")
        assert _sub_period(1) == 0
        print("  PASS: sub_period(1) = 0")

    def test_sub_period_t2(self, capsys):
        print("\n[TestHelpers] Testing sub_period(2) == 1  (second sub-period of epoch 1)")
        assert _sub_period(2) == 1
        print("  PASS: sub_period(2) = 1")

    def test_sub_period_t3(self, capsys):
        print("\n[TestHelpers] Testing sub_period(3) == 0  (first sub-period of epoch 2)")
        assert _sub_period(3) == 0
        print("  PASS: sub_period(3) = 0")

    def test_sub_period_t6(self, capsys):
        print("\n[TestHelpers] Testing sub_period(6) == 3")
        assert _sub_period(6) == 3
        print("  PASS: sub_period(6) = 3")

    def test_epoch_boundary_consistency(self, capsys):
        print("\n[TestHelpers] Testing round-trip: (2^epoch - 1) + sub_period == t for t in 0..19")
        for t in range(20):
            e = _epoch(t)
            s = _sub_period(t)
            assert (1 << e) - 1 + s == t, f"Round-trip failed for t={t}"
        print("  PASS: all 20 values reconstruct correctly")


# ---------------------------------------------------------------------------
# Key generation tests
# ---------------------------------------------------------------------------

class TestKeygen:
    def test_keygen_returns_pk_and_sk(self, capsys):
        print("\n[TestKeygen] Scenario: keygen should return a non-None pk and sk")
        mmm = MMM(1)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        assert pk is not None
        assert sk is not None
        print(f"  PASS: pk={pk.hex()[:16]}..., sk has {len(sk)} fields")

    def test_sk_has_required_fields(self, capsys):
        print("\n[TestKeygen] Scenario: sk dict must contain all required fields after keygen")
        required = ('sk_main', 'pk_main', 'cert', 'pk_B', 'sk_B', 'seed_chain', 'curr_epoch')
        mmm = MMM(1)
        _, sk = mmm.keygen(secrets.token_bytes(32))
        for key in required:
            assert key in sk, f"sk missing field: {key}"
            print(f"  PASS: sk['{key}'] present")

    def test_initial_epoch_is_zero(self, capsys):
        print("\n[TestKeygen] Scenario: freshly generated sk should start at epoch 0")
        mmm = MMM(1)
        _, sk = mmm.keygen(secrets.token_bytes(32))
        assert sk['curr_epoch'] == 0
        print(f"  PASS: curr_epoch = {sk['curr_epoch']}")

    def test_pk_is_bytes(self, capsys):
        print("\n[TestKeygen] Scenario: public key must be bytes")
        mmm = MMM(1)
        pk, _ = mmm.keygen(secrets.token_bytes(32))
        assert isinstance(pk, bytes)
        print(f"  PASS: pk is bytes, length={len(pk)}")

    def test_different_seeds_produce_different_keys(self, capsys):
        print("\n[TestKeygen] Scenario: two different random seeds must produce distinct public keys")
        mmm = MMM(1)
        pk1, _ = mmm.keygen(secrets.token_bytes(32))
        pk2, _ = mmm.keygen(secrets.token_bytes(32))
        assert pk1 != pk2
        print("  PASS: pk1 != pk2")

    def test_same_seed_produces_same_keys(self, capsys):
        print("\n[TestKeygen] Scenario: the same seed must deterministically reproduce the same keys")
        seed = secrets.token_bytes(32)
        pk1, sk1 = MMM(1).keygen(seed)
        pk2, sk2 = MMM(1).keygen(seed)
        assert pk1 == pk2
        assert sk1['pk_B'] == sk2['pk_B']
        print("  PASS: pk and pk_B are identical across two keygen calls with the same seed")


# ---------------------------------------------------------------------------
# Valid signature / verify tests
# ---------------------------------------------------------------------------

class TestValidSignatures:
    def test_sign_and_verify_t0(self, capsys):
        print("\n[TestValidSignatures] Scenario: sign at t=0 and verify should succeed")
        mmm = MMM(1)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        msg = b"hello at t=0"
        sig = mmm.sign(sk, msg, 0)
        result = mmm.verify(pk, msg, sig, 0)
        assert result is True
        print(f"  PASS: verify(msg, sig, t=0) = {result}")

    def test_sign_and_verify_multiple_time_periods(self, capsys):
        print("\n[TestValidSignatures] Scenario: sign and verify across multiple consecutive time periods")
        mmm, pk, results = full_lifecycle(2)
        for _, msg, sig, t in results:
            result = mmm.verify(pk, msg, sig, t)
            assert result is True, f"valid sig failed at t={t}"
            print(f"  PASS: verify(msg, sig, t={t}) = {result}  [epoch={_epoch(t)}, sub={_sub_period(t)}]")

    def test_sign_and_verify_across_epoch_boundary(self, capsys):
        print("\n[TestValidSignatures] Scenario: signatures from different epochs all verify correctly")
        mmm = MMM(2)
        seed = secrets.token_bytes(32)
        pk, sk = mmm.keygen(seed)

        msg0 = b"epoch 0"
        sig0 = mmm.sign(sk, msg0, 0)
        print("  Signed at t=0 (epoch 0)")

        sk = mmm.update(sk, 1)
        msg1 = b"epoch 1 start"
        sig1 = mmm.sign(sk, msg1, 1)
        print("  Signed at t=1 (epoch 1, new epoch_tree)")

        sk = mmm.update(sk, 2)
        sk = mmm.update(sk, 3)
        msg3 = b"epoch 2 start"
        sig3 = mmm.sign(sk, msg3, 3)
        print("  Signed at t=3 (epoch 2, another new epoch_tree)")

        assert mmm.verify(pk, msg0, sig0, 0) is True
        assert mmm.verify(pk, msg1, sig1, 1) is True
        assert mmm.verify(pk, msg3, sig3, 3) is True
        print("  PASS: all three epoch-boundary signatures verify correctly")

    def test_sign_returns_four_tuple(self, capsys):
        print("\n[TestValidSignatures] Scenario: signature must be a 4-tuple (pk_B, cert, sign, t)")
        mmm = MMM(1)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        sig = mmm.sign(sk, b"msg", 0)
        assert isinstance(sig, tuple) and len(sig) == 4
        print(f"  PASS: signature is a tuple of length {len(sig)}")

    def test_signature_pk_B_matches_sk(self, capsys):
        print("\n[TestValidSignatures] Scenario: pk_B embedded in signature must match sk['pk_B']")
        mmm = MMM(1)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        sig = mmm.sign(sk, b"msg", 0)
        pk_B, cert, sign, t = sig
        assert pk_B == sk['pk_B']
        print(f"  PASS: sig.pk_B matches sk['pk_B'] ({pk_B.hex()[:16]}...)")


# ---------------------------------------------------------------------------
# Forward security tests
# ---------------------------------------------------------------------------

class TestForwardSecurity:
    """
    After updating to time t, any signature produced with the old (pre-update)
    secret key for future time periods must NOT verify.
    """

    def test_old_sk_cannot_forge_at_future_time_same_epoch(self, capsys):
        print("\n[TestForwardSecurity] Scenario: attacker captures sk at t=1; tries to sign at t=2 (same epoch)")
        print("  Expected: verify returns False — the updated sk_B no longer works for past sub-periods")
        mmm = MMM(2)
        pk, sk0 = mmm.keygen(secrets.token_bytes(32))

        sk0 = mmm.update(sk0, 1)
        sk_captured = copy.deepcopy(sk0)
        print("  Attacker captures sk at t=1 (epoch=1, sub=0)")

        sk0 = mmm.update(sk0, 2)
        print("  Legitimate signer advances to t=2 (epoch=1, sub=1)")

        forged_sig = mmm.sign(sk_captured, b"forged future message", 2)
        result = mmm.verify(pk, b"forged future message", forged_sig, 2)
        assert result is False
        print(f"  PASS: verify(forged_sig, t=2) = {result}")

    def test_old_sk_cannot_forge_at_future_epoch(self, capsys):
        print("\n[TestForwardSecurity] Scenario: attacker captures sk at epoch 0; tries to sign for epoch 1")
        print("  Expected: TypeError — old epoch-0 sk_B (raw bytes) is incompatible with epoch-1 SumCompose tree")
        mmm = MMM(2)
        pk, sk = mmm.keygen(secrets.token_bytes(32))

        sk_epoch0 = copy.deepcopy(sk)
        print("  Attacker captures sk at t=0 (epoch=0)")

        sk = mmm.update(sk, 1)
        print("  Legitimate signer advances to t=1 (epoch=1, new epoch_tree built)")

        with pytest.raises(TypeError):
            mmm.sign(sk_epoch0, b"forged at epoch 1", 1)
        print("  PASS: signing with stale epoch-0 sk raises TypeError (key type mismatch)")

    def test_compromised_sk_t0_cannot_sign_for_t1(self, capsys):
        print("\n[TestForwardSecurity] Scenario: sk captured at t=0 cannot produce a valid signature for t=1")
        print("  Expected: legitimate sig at t=1 verifies True; forged attempt raises TypeError")
        mmm = MMM(2)
        pk, sk0 = mmm.keygen(secrets.token_bytes(32))
        sk_captured = copy.deepcopy(sk0)
        print("  Attacker captures sk at t=0")

        sk1 = mmm.update(sk0, 1)
        legitimate_sig = mmm.sign(sk1, b"legit", 1)
        result = mmm.verify(pk, b"legit", legitimate_sig, 1)
        assert result is True
        print(f"  Legitimate sig at t=1 verifies: {result}")

        with pytest.raises(TypeError):
            mmm.sign(sk_captured, b"forged", 1)
        print("  PASS: forgery attempt with captured t=0 sk raises TypeError")


# ---------------------------------------------------------------------------
# Rejection tests
# ---------------------------------------------------------------------------

class TestRejection:
    def test_wrong_message_fails_verify(self, capsys):
        print("\n[TestRejection] Scenario: verifying a signature against the wrong message")
        mmm = MMM(1)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        sig = mmm.sign(sk, b"correct message", 0)
        result = mmm.verify(pk, b"wrong message", sig, 0)
        assert result is False
        print(f"  PASS: verify(wrong_msg, sig, t=0) = {result}")

    def test_wrong_time_period_fails_verify(self, capsys):
        print("\n[TestRejection] Scenario: replaying a t=1 signature at t=0")
        mmm = MMM(2)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        sk = mmm.update(sk, 1)
        msg = b"message"
        sig = mmm.sign(sk, msg, 1)
        result = mmm.verify(pk, msg, sig, 0)
        assert result is False
        print(f"  PASS: verify(msg, sig_t1, t=0) = {result}")

    def test_cross_time_forgery_fails(self, capsys):
        print("\n[TestRejection] Scenario: no signature from time t_i should verify at a different t_j")
        mmm, pk, results = full_lifecycle(2)
        failures = 0
        for _, msg_i, sig_i, t_i in results:
            for _, _, _, t_j in results:
                if t_i == t_j:
                    continue
                result = mmm.verify(pk, msg_i, sig_i, t_j)
                assert result is False, f"sig from t={t_i} incorrectly verified at t={t_j}"
                failures += 1
        n = len(results)
        print(f"  PASS: all {n*(n-1)} cross-time pairs correctly rejected")

    def test_wrong_pk_fails_verify(self, capsys):
        print("\n[TestRejection] Scenario: verifying with a different party's public key")
        mmm = MMM(1)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        wrong_pk, _ = mmm.keygen(secrets.token_bytes(32))
        msg = b"message"
        sig = mmm.sign(sk, msg, 0)
        result = mmm.verify(wrong_pk, msg, sig, 0)
        assert result is False
        print(f"  PASS: verify(wrong_pk, msg, sig, t=0) = {result}")

    def test_tampered_pk_B_in_signature_fails(self, capsys):
        print("\n[TestRejection] Scenario: attacker flips bits in the epoch public key (pk_B) inside the signature")
        mmm = MMM(1)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        msg = b"tamper test"
        pk_B, cert, sign, t = mmm.sign(sk, msg, 0)
        tampered_pk_B = bytes(b ^ 0xFF for b in pk_B[:32]) + pk_B[32:]
        tampered_sig = (tampered_pk_B, cert, sign, t)
        result = mmm.verify(pk, msg, tampered_sig, 0)
        assert result is False
        print(f"  PASS: verify(msg, tampered_sig, t=0) = {result}")

    def test_tampered_message_fails(self, capsys):
        print("\n[TestRejection] Scenario: message is modified after signing")
        mmm = MMM(1)
        pk, sk = mmm.keygen(secrets.token_bytes(32))
        sig = mmm.sign(sk, b"original", 0)
        result = mmm.verify(pk, b"tampered", sig, 0)
        assert result is False
        print(f"  PASS: verify(tampered_msg, sig, t=0) = {result}")


# ---------------------------------------------------------------------------
# Update / state advancement tests
# ---------------------------------------------------------------------------

class TestUpdate:
    def test_update_increments_within_same_epoch(self, capsys):
        print("\n[TestUpdate] Scenario: updating t=1->t=2 stays within epoch 1, no epoch change")
        mmm = MMM(2)
        _, sk = mmm.keygen(secrets.token_bytes(32))
        sk = mmm.update(sk, 1)
        assert sk['curr_epoch'] == 1
        print(f"  After update to t=1: curr_epoch = {sk['curr_epoch']}")
        sk = mmm.update(sk, 2)
        assert sk['curr_epoch'] == 1
        print(f"  After update to t=2: curr_epoch = {sk['curr_epoch']} (still epoch 1)")
        print("  PASS")

    def test_update_changes_epoch(self, capsys):
        print("\n[TestUpdate] Scenario: updating across epoch boundaries increments curr_epoch")
        mmm = MMM(2)
        _, sk = mmm.keygen(secrets.token_bytes(32))
        print(f"  Initial curr_epoch = {sk['curr_epoch']}")
        assert sk['curr_epoch'] == 0
        sk = mmm.update(sk, 1)
        print(f"  After t=1: curr_epoch = {sk['curr_epoch']}")
        assert sk['curr_epoch'] == 1
        sk = mmm.update(sk, 3)
        print(f"  After t=3: curr_epoch = {sk['curr_epoch']}")
        assert sk['curr_epoch'] == 2
        print("  PASS")

    def test_update_rotates_cert_on_epoch_change(self, capsys):
        print("\n[TestUpdate] Scenario: cert must be refreshed when entering a new epoch")
        mmm = MMM(2)
        _, sk = mmm.keygen(secrets.token_bytes(32))
        cert_epoch0 = sk['cert']
        sk = mmm.update(sk, 1)
        assert sk['cert'] != cert_epoch0
        print("  PASS: cert changed on epoch transition (epoch 0 -> epoch 1)")

    def test_update_rotates_pk_B_on_epoch_change(self, capsys):
        print("\n[TestUpdate] Scenario: pk_B (epoch public key) must be replaced on epoch change")
        mmm = MMM(2)
        _, sk = mmm.keygen(secrets.token_bytes(32))
        pk_B_epoch0 = sk['pk_B']
        sk = mmm.update(sk, 1)
        assert sk['pk_B'] != pk_B_epoch0
        print("  PASS: pk_B rotated on epoch transition (epoch 0 -> epoch 1)")

    def test_update_preserves_sk_main_pk(self, capsys):
        print("\n[TestUpdate] Scenario: the main public key (pk_main) must never change across updates")
        mmm = MMM(2)
        _, sk = mmm.keygen(secrets.token_bytes(32))
        pk_main_before = sk['pk_main']
        sk = mmm.update(sk, 1)
        assert sk['pk_main'] == pk_main_before
        print("  PASS: pk_main unchanged after epoch transition")

    def test_sk_has_sk_B_after_epoch_change(self, capsys):
        print("\n[TestUpdate] Scenario: sk['sk_B'] must be populated with the new epoch secret key after update")
        mmm = MMM(2)
        _, sk = mmm.keygen(secrets.token_bytes(32))
        sk = mmm.update(sk, 1)
        assert 'sk_B' in sk and sk['sk_B'] is not None
        print("  PASS: sk['sk_B'] is present and non-None after epoch transition")
