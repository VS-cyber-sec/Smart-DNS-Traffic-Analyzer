
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dns_analyzer.detection import FrequencyTracker, SpoofingDetector
from dns_analyzer.anomaly   import AnomalyDetector
from unittest.mock import MagicMock


# =============================================================================
# TESTS FOR SpoofingDetector
# =============================================================================

class TestSpoofingDetector:
    """
    Tests for all 3 spoofing detection checks:
    1. Low TTL (< ttl_low threshold)
    2. High TTL (> ttl_high threshold)
    3. Transaction ID mismatch
    """

    def _make_dns(self, ttl=None, txid=100, qname=b"test.com."):
        """
        Helper: creates a mock DNS response object.
        Used in multiple tests — avoids repeating mock setup code.

        PARAMETERS:
            ttl   = TTL value for the answer record (None = no answer)
            txid  = transaction ID (0-65535)
            qname = domain name as bytes

        RETURNS:
            MagicMock that behaves like a Scapy DNS layer
        """
        mock_dns = MagicMock()
        mock_dns.id = txid

        if ttl is not None:
            # Configure mock answer record with the given TTL
            mock_dns.an       = MagicMock()
            mock_dns.an.ttl   = ttl
        else:
            # No answer (query packet, not response)
            mock_dns.an = None

        mock_dns.qd       = MagicMock()
        mock_dns.qd.qname = qname

        return mock_dns

    def test_normal_ttl_not_flagged(self):
        """
        WHAT: A response with normal TTL (300 seconds) should NOT be flagged.
        WHY: TTL of 5 minutes is completely normal for most DNS records.
        """
        detector = SpoofingDetector(ttl_low=5, ttl_high=86400)
        dns      = self._make_dns(ttl=300, txid=42)
        # Record the query first
        detector.record_query(dns)
        # Check the response (same txid = matches)
        spoofed, reason = detector.check_response(dns)
        assert spoofed is False, f"Normal TTL=300 should not be flagged. Got: {reason}"

    def test_low_ttl_detected(self):
        """
        WHAT: A response with TTL = 2 (below threshold of 5) should be flagged.
        WHY: Attackers set very low TTL to refresh poisoned entries quickly.
        """
        detector = SpoofingDetector(ttl_low=5, ttl_high=86400)
        dns      = self._make_dns(ttl=2, txid=99)
        spoofed, reason = detector.check_response(dns)
        assert spoofed is True,         "Low TTL should be flagged as spoofing"
        assert "low_ttl" in reason,     f"Reason should mention low_ttl. Got: {reason}"
        assert "2s" in reason,          f"Reason should include TTL value. Got: {reason}"

    def test_ttl_zero_detected(self):
        """
        WHAT: TTL=0 (seen from ad networks in your capture) should be flagged.
        WHY: Your capture showed TTL=0 from ad tech — confirms this works.
        """
        detector = SpoofingDetector(ttl_low=5, ttl_high=86400)
        dns      = self._make_dns(ttl=0, txid=55)
        spoofed, reason = detector.check_response(dns)
        assert spoofed is True, "TTL=0 should always be flagged"

    def test_high_ttl_detected(self):
        """
        WHAT: A response with TTL > 86400 (1 day) should be flagged.
        WHY: Attacker sets high TTL so the poisoned entry persists in caches.
        EXAMPLE: TTL=604800 = 1 week — no real server does this.
        """
        detector  = SpoofingDetector(ttl_low=5, ttl_high=86400)
        dns       = self._make_dns(ttl=604800, txid=77)  # 1 week
        spoofed, reason = detector.check_response(dns)
        assert spoofed is True,         "High TTL should be flagged"
        assert "high_ttl" in reason,    f"Reason should mention high_ttl. Got: {reason}"

    def test_txid_mismatch_detected(self):
        """
        WHAT: If the response's transaction ID doesn't match the query's ID,
              it should be flagged as a possible spoofed response.
        WHY: DNS spoofing involves injecting a forged response. The attacker
             guesses the transaction ID. If they guess wrong, we catch them.
        """
        detector = SpoofingDetector(ttl_low=5, ttl_high=86400)

        # Step 1: Record the query with transaction ID = 1000
        query_dns     = self._make_dns(ttl=None, txid=1000,
                                       qname=b"bank.example.com.")
        detector.record_query(query_dns)

        # Step 2: Receive a response with a DIFFERENT transaction ID = 9999
        # This simulates an attacker who guessed the wrong ID
        response_dns  = self._make_dns(ttl=300, txid=9999,
                                       qname=b"bank.example.com.")
        spoofed, reason = detector.check_response(response_dns)
        assert spoofed is True,           "TXID mismatch should be flagged"
        assert "txid_mismatch" in reason, f"Got reason: {reason}"

    def test_txid_match_not_flagged(self):
        """
        WHAT: Matching transaction IDs (normal DNS) should NOT be flagged.
        WHY: Legitimate DNS responses always echo back the query's txid.
        """
        detector = SpoofingDetector(ttl_low=5, ttl_high=86400)

        query_dns    = self._make_dns(ttl=None, txid=1234,
                                      qname=b"google.com.")
        detector.record_query(query_dns)

        response_dns = self._make_dns(ttl=300, txid=1234,
                                      qname=b"google.com.")
        spoofed, reason = detector.check_response(response_dns)
        assert spoofed is False, f"Matching TXID should not be flagged. Got: {reason}"

    def test_response_without_answer_not_flagged(self):
        """
        WHAT: A DNS response with no answer section (NXDOMAIN) should not crash.
        WHY: NXDOMAIN = domain doesn't exist. No answer = no TTL to check.
        """
        detector = SpoofingDetector(ttl_low=5, ttl_high=86400)
        dns      = self._make_dns(ttl=None, txid=42)  # no answer
        spoofed, reason = detector.check_response(dns)
        assert spoofed is False, "Response with no answer should not be flagged"


# =============================================================================
# TESTS FOR AnomalyDetector
# =============================================================================

class TestAnomalyDetector:
    """
    Tests for the Isolation Forest anomaly detector.

    WHAT WE'RE TESTING:
    - During warmup, no anomalies are flagged
    - After warmup, clearly anomalous packets are detected
    - Stats are reported correctly
    - Reset works correctly
    """

    def _make_normal_features(self, query="google.com"):
        """Creates a feature dict for a normal-looking domain."""
        return {
            "query":           query,
            "length":          len(query),
            "entropy":         2.8,
            "subdomains":      1,
            "consonant_ratio": 0.5,
            "numeric_ratio":   0.0,
            "unique_ratio":    0.7,
            "longest_label":   6,
            "has_hex":         0,
        }

    def _make_tunneling_features(self, query="aGVsbG9Xb3JsZA.evil.com"):
        """Creates a feature dict for a tunneling-looking domain."""
        return {
            "query":           query,
            "length":          len(query),
            "entropy":         4.2,
            "subdomains":      2,
            "consonant_ratio": 0.85,
            "numeric_ratio":   0.1,
            "unique_ratio":    0.98,
            "longest_label":   14,
            "has_hex":         0,
        }

    def test_not_ready_during_warmup(self):
        """
        WHAT: Before warmup completes, is_ready should be False.
        WHY: We need enough data to learn what "normal" looks like before
             we can flag anything as abnormal.
        """
        detector = AnomalyDetector(warmup=300)
        assert detector.is_ready is False, (
            "Detector should not be ready before warmup completes"
        )

    def test_no_anomaly_during_warmup(self):
        """
        WHAT: During warmup, score() should return (False, 0.0) always.
        WHY: We can't reliably detect anomalies without a baseline.
             False positives during warmup would be very noisy.
        """
        detector = AnomalyDetector(warmup=100)
        # Feed it some packets but not enough to complete warmup
        for _ in range(50):
            is_anomaly, score = detector.score(
                self._make_tunneling_features())
            assert is_anomaly is False, (
                "Should not flag anomalies during warmup"
            )
            assert score == 0.0, (
                f"Score should be 0.0 during warmup, got {score}"
            )

    def test_becomes_ready_after_warmup(self):
        """
        WHAT: After seeing enough packets, is_ready becomes True.
        WHY: Warmup period completes → model trains → can start scoring.
        """
        # Use a small warmup for testing speed
        detector = AnomalyDetector(warmup=50, retrain_interval=50)
        features = self._make_normal_features()

        # Feed enough packets to trigger training
        for _ in range(55):
            detector.score(features)

        assert detector.is_ready is True, (
            "Detector should be ready after warmup completes"
        )

    def test_warmup_progress_increases(self):
        """
        WHAT: warmup_progress should increase from 0.0 to 1.0 during warmup.
        WHY: Used by GUI to show a progress bar during warmup phase.
        """
        detector = AnomalyDetector(warmup=100)
        assert detector.warmup_progress == 0.0

        for _ in range(50):
            detector.score(self._make_normal_features())

        assert 0.4 < detector.warmup_progress <= 0.6, (
            f"After 50/100 packets, progress should be ~0.5. "
            f"Got {detector.warmup_progress}"
        )

    def test_reset_clears_state(self):
        """
        WHAT: After reset(), the detector starts fresh — as if newly created.
        WHY: When monitoring restarts, old traffic patterns shouldn't affect
             detection of new traffic.
        """
        detector = AnomalyDetector(warmup=50, retrain_interval=50)
        # Train it
        for _ in range(60):
            detector.score(self._make_normal_features())

        assert detector.is_ready is True
        detector.reset()

        # Now it should be untrained again
        assert detector.is_ready is False, "After reset, should not be ready"
        assert detector.warmup_progress == 0.0
        assert detector._packets_seen == 0

    def test_get_stats_returns_dict(self):
        """
        WHAT: get_stats() should return a dict with expected keys.
        WHY: GUI displays these stats to the user.
        """
        detector = AnomalyDetector(warmup=50)
        stats    = detector.get_stats()

        expected_keys = [
            "trained", "warmup_progress", "packets_seen",
            "buffer_size", "anomalies_flagged", "contamination",
        ]
        for key in expected_keys:
            assert key in stats, f"Stats missing key: '{key}'"


# =============================================================================
# TEST RUNNER
# =============================================================================
if __name__ == "__main__":
    import subprocess
    raise SystemExit(
        subprocess.call([sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"])
    )
# pyright: reportMissingImports=false
