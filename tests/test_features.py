import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dns_analyzer.features  import calculate_entropy, CONSONANTS, HEX_CHARS
from dns_analyzer.lists     import is_match, get_wildcard_pattern
from dns_analyzer.detection import FrequencyTracker, SpoofingDetector


# =============================================================================
# TESTS FOR calculate_entropy()
# =============================================================================

class TestCalculateEntropy:

    def test_empty_string_returns_zero(self):
        """Empty string → 0.0 (no characters = no randomness)."""
        assert calculate_entropy("") == 0.0

    def test_single_repeated_char_returns_zero(self):
        """All same character → 0.0 (completely predictable)."""
        assert calculate_entropy("aaaaaaa") == 0.0

    def test_normal_domain_low_entropy(self):
        """Human-readable domain names score below 3.5."""
        result = calculate_entropy("google.com")
        assert result < 3.5, f"Expected < 3.5, got {result:.3f}"

    def test_normal_mail_domain_low_entropy(self):
        """Another normal domain — stays below detection threshold."""
        result = calculate_entropy("mail.google.com")
        assert result < 3.5, f"Expected < 3.5, got {result:.3f}"

    def test_tunneling_domain_high_entropy(self):
        """Base64-encoded subdomains score above 3.8 (detection threshold)."""
        # aGVsbG9Xb3JsZA = base64("helloWorld")
        result = calculate_entropy("aGVsbG9Xb3JsZA.example.com")
        assert result > 3.8, f"Expected > 3.8, got {result:.3f}"

    def test_hex_encoded_high_entropy(self):
        """Hex-encoded payloads also score high entropy."""
        result = calculate_entropy("a3f9b2c1d4e5f6a7.evil.com")
        assert result > 3.5, f"Expected > 3.5, got {result:.3f}"

    def test_entropy_always_non_negative(self):
        """Entropy is information content — can never be negative."""
        for s in ["a", "aa", "ab", "abc", "google.com",
                  "aGVsbG9Xb3JsZA", "test", "12345678"]:
            assert calculate_entropy(s) >= 0, f"Negative entropy for '{s}'"

    def test_entropy_increases_with_randomness(self):
        """More random strings have higher entropy."""
        low  = calculate_entropy("aaaaabbbbb")  # 2 unique chars
        high = calculate_entropy("abcdefghij")  # 10 unique chars
        assert low < high, f"low={low:.3f} should be < high={high:.3f}"

    def test_entropy_is_float(self):
        """Return type is always float."""
        assert isinstance(calculate_entropy("test.com"), float)


# =============================================================================
# TESTS FOR FrequencyTracker
# =============================================================================

class TestFrequencyTracker:

    def test_first_query_returns_one(self):
        """First query to a domain returns 1."""
        tracker = FrequencyTracker(window_secs=10)
        assert tracker.get_frequency("test.example.com") == 1

    def test_repeated_queries_increment_count(self):
        """N queries to same domain returns N."""
        tracker = FrequencyTracker(window_secs=10)
        for i in range(1, 6):
            result = tracker.get_frequency("repeated.example.com")
            assert result == i, f"After {i} queries expected {i}, got {result}"

    def test_different_domains_tracked_separately(self):
        """Two different domains have independent counters."""
        tracker = FrequencyTracker(window_secs=10)
        tracker.get_frequency("domain-a.com")
        tracker.get_frequency("domain-a.com")
        tracker.get_frequency("domain-b.com")

        assert tracker.get_frequency("domain-a.com") == 3
        assert tracker.get_frequency("domain-b.com") == 2

    def test_reset_clears_all_counts(self):
        """After reset(), every domain starts fresh from 1."""
        tracker = FrequencyTracker(window_secs=10)
        for _ in range(5):
            tracker.get_frequency("test.com")
        tracker.reset()
        assert tracker.get_frequency("test.com") == 1

    def test_frequency_is_integer(self):
        """get_frequency() always returns an int."""
        tracker = FrequencyTracker(window_secs=10)
        assert isinstance(tracker.get_frequency("test.com"), int)


# =============================================================================
# TESTS FOR is_match()  — FIXED SECTION
# =============================================================================

class TestIsMatch:

    def test_exact_match(self):
        """Exact pattern matches the exact domain."""
        matched, pattern = is_match("google.com", ["google.com"])
        assert matched is True
        assert pattern == "google.com"

    def test_exact_no_match(self):
        """Domain not in list returns (False, None)."""
        matched, pattern = is_match("evil.com", ["google.com"])
        assert matched is False
        assert pattern is None

    def test_wildcard_matches_subdomain(self):
        """*.google.com matches mail.google.com."""
        matched, _ = is_match("mail.google.com", ["*.google.com"])
        assert matched is True

    def test_wildcard_matches_deep_subdomain(self):
        """
        *.google.com matches signaler-pa.clients6.google.com.
        This was the false positive from your real DNS capture.
        """
        matched, _ = is_match(
            "signaler-pa.clients6.google.com", ["*.google.com"])
        assert matched is True

    def test_wildcard_does_not_match_different_tld(self):
        """*.google.com does NOT match test.google.net (different TLD)."""
        matched, _ = is_match("test.google.net", ["*.google.com"])
        assert matched is False

    # -------------------------------------------------------------------------
    # FIX: Three tests replacing the single broken test_trailing_dot_handled
    # -------------------------------------------------------------------------

    def test_trailing_dot_base_domain_matches_exact_pattern(self):
      
        matched, pattern = is_match("google.com.", ["google.com"])
        assert matched is True, (
            "google.com. (DNS trailing dot) should match exact pattern 'google.com'")
        assert pattern == "google.com"

    def test_trailing_dot_subdomain_matches_wildcard(self):
        
        matched, _ = is_match("mail.google.com.", ["*.google.com"])
        assert matched is True, (
            "mail.google.com. should match *.google.com after dot strip")

    def test_trailing_dot_base_domain_does_NOT_match_wildcard(self):

        matched, _ = is_match("google.com.", ["*.google.com"])
        assert matched is False, (
            "google.com. correctly does NOT match *.google.com — "
            "it is the base domain, not a subdomain. "
            "Use exact pattern 'google.com' for the base domain.")

    def test_case_insensitive(self):
        """DNS is case-insensitive. MAIL.GOOGLE.COM matches *.google.com."""
        matched, _ = is_match("MAIL.GOOGLE.COM", ["*.google.com"])
        assert matched is True

    def test_empty_pattern_list(self):
        """Empty list always returns (False, None)."""
        matched, pattern = is_match("google.com", [])
        assert matched is False
        assert pattern is None

    def test_first_matching_pattern_returned(self):
        """When multiple patterns match, the first one is returned."""
        patterns = ["*.google.com", "*.com", "google.com"]
        matched, pattern = is_match("mail.google.com", patterns)
        assert matched is True
        assert pattern == "*.google.com"

    def test_empty_query_returns_false(self):
        """Empty query string always returns (False, None)."""
        matched, pattern = is_match("", ["*.google.com", "google.com"])
        assert matched is False
        assert pattern is None

    def test_query_with_only_dot_returns_false(self):
        """DNS root query '.' returns (False, None) after stripping."""
        matched, _ = is_match(".", ["*.google.com"])
        assert matched is False


# =============================================================================
# TESTS FOR get_wildcard_pattern()
# =============================================================================

class TestGetWildcardPattern:

    def test_generates_wildcard_for_subdomain(self):
        """mail.google.com → *.google.com"""
        assert get_wildcard_pattern("mail.google.com") == "*.google.com"

    def test_deep_subdomain_uses_last_two_parts(self):
        """a.b.c.google.com → *.google.com"""
        assert get_wildcard_pattern("a.b.c.google.com") == "*.google.com"

    def test_trailing_dot_handled(self):
        """mail.google.com. → *.google.com"""
        assert get_wildcard_pattern("mail.google.com.") == "*.google.com"

    def test_two_part_domain(self):
        """google.com → *.google.com"""
        assert get_wildcard_pattern("google.com") == "*.google.com"


# =============================================================================
# INTEGRATION TEST — extract_features() with mock packet
# =============================================================================

class TestFeatureExtraction:

    def test_extract_features_from_mock_packet(self):
        """
        Tests extract_features() returns correct structure.
        Uses unittest.mock to simulate a Scapy packet — no admin needed.
        """
        from unittest.mock import MagicMock
        from dns_analyzer.features import extract_features

        # Build a mock DNS query packet for "google.com"
        mock_packet           = MagicMock()
        mock_packet.haslayer.return_value = True

        mock_dns              = MagicMock()
        mock_dns.qr           = 0               # 0 = query
        mock_dns.qd           = MagicMock()
        mock_dns.qd.qname     = b"google.com."  # bytes as Scapy returns
        mock_dns.an           = None            # queries have no answer

        mock_packet.__getitem__ = lambda self, key: mock_dns

        result = extract_features(mock_packet)

        # All expected keys must exist
        for key in ["query", "length", "entropy", "subdomains", "ttl",
                    "timestamp", "consonant_ratio", "numeric_ratio",
                    "unique_ratio", "longest_label", "has_hex"]:
            assert key in result, f"Key '{key}' missing from result"

        # Values must be sensible for "google.com"
        assert result["query"]   == "google.com"
        assert result["length"]  == len("google.com")
        assert result["ttl"]     is None        # queries have no TTL
        assert 0 < result["entropy"] < 5
        assert 0 <= result["consonant_ratio"] <= 1
        assert 0 <= result["numeric_ratio"]   <= 1
        assert 0 <= result["unique_ratio"]    <= 1


# =============================================================================
# TEST RUNNER
# =============================================================================
if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
# pyright: reportMissingImports=false
