import time                          # for time.time() timestamps
from collections import defaultdict  # auto-creates empty lists for new keys

class FrequencyTracker:

    def __init__(self, window_secs=10):
        # window_secs: how many seconds to look back
        # Default 10 = "how many queries in the last 10 seconds?"
        self.window = window_secs

        # defaultdict(list): a dict where every new key automatically gets
        # an empty list []. Prevents KeyError when a new domain is seen.
        # Structure: {"google.com": [1709500801.2, 1709500802.5, ...], ...}
        self.counts = defaultdict(list)

    def get_frequency(self, query):
        now = time.time()   # current time as float (seconds since 1970)

        # Step 1: Remove timestamps older than the window
        # List comprehension: keep only timestamps where
        # (now - t) < window, i.e. less than 10 seconds ago
        # This is the "sliding" part — old timestamps fall off automatically
        self.counts[query] = [
            t for t in self.counts[query]
            if now - t < self.window
        ]

        # Step 2: Add the current timestamp
        self.counts[query].append(now)

        # Step 3: Return count = how many queries in the last 10 seconds
        return len(self.counts[query])

    def reset(self):
        """Clear all frequency data (call when monitoring restarts)."""
        self.counts.clear()

class SpoofingDetector:

    def __init__(self, ttl_low=5, ttl_high=86400):
        # ttl_low: TTL below this → suspicious (low_ttl)
        # Default 5 (not 10) to reduce false positives from ad networks
        self.ttl_low = ttl_low

        # ttl_high: TTL above this → suspicious (high_ttl)
        # 86400 = 24 hours. Anything above 1 day is unusual.
        self.ttl_high = ttl_high

        # pending: stores {domain_bytes: transaction_id} for in-flight queries
        # When we see a query, store its ID here.
        # When we see the response, compare its ID to what we stored.
        # If they don't match → transaction ID mismatch (possible spoofing)
        self.pending = {}

    def record_query(self, dns):

        if dns.qd:
            # dns.qd.qname = domain name as bytes e.g. b"google.com."
            # dns.id = 16-bit transaction ID (0–65535)
            self.pending[dns.qd.qname] = dns.id

    def check_response(self, dns):

        if not dns.an:
            return False, "none"

        ttl = dns.an.ttl   # extract the TTL value from the response

        # --- Check 1: Abnormally low TTL ---
        # Real DNS servers almost never use TTL < 5 seconds.
        # Attacker uses low TTL so poisoned entry refreshes quickly.
        if ttl < self.ttl_low:
            return True, f"low_ttl ({ttl}s)"

        # --- Check 2: Abnormally high TTL ---
        # TTL above 1 day is very unusual for most domain types.
        # Attacker uses high TTL so poisoned entry persists in caches.
        if ttl > self.ttl_high:
            return True, f"high_ttl ({ttl}s)"

        # --- Check 3: Transaction ID mismatch ---
        if dns.qd:
            qname = dns.qd.qname   # domain name bytes

            # .pop(qname, None): get and remove the stored ID
            # Returns None if we never saw the query (e.g. started mid-session)
            expected_id = self.pending.pop(qname, None)

            # If we have a stored ID AND it doesn't match the response ID
            # → someone sent a response with a wrong/forged transaction ID
            if expected_id is not None and expected_id != dns.id:
                return True, "txid_mismatch"

        # All checks passed — looks legitimate
        return False, "none"

    def cleanup_old_pending(self, max_age_secs=5):
        if len(self.pending) > 1000:
            self.pending.clear()
