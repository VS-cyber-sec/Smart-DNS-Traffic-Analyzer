import time       # for timestamps and rate limiting
import logging    # for logging errors without crashing
import importlib  # for optional runtime imports
from typing import Any

# requests: HTTP library for making API calls
# Install with: pip install requests
requests: Any = None
try:
    requests = importlib.import_module("requests")
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# Set up a logger for this module
# __name__ = "dns_analyzer.threat_intel"
logger = logging.getLogger(__name__)


class ThreatIntelChecker:

    VT_URL = "https://www.virustotal.com/api/v3/domains/{}"

    # How long to cache a result before re-querying (seconds)
    # 3600 = 1 hour. Domain reputation doesn't change minute-to-minute.
    CACHE_TTL = 3600

    # Minimum seconds between API calls (rate limiting)
    # VirusTotal free tier: 4 requests per minute = 15 seconds between calls
    RATE_LIMIT_SECS = 15

    def __init__(self, api_key=None):
        self.api_key = api_key

        # Cache: {domain: {"result": {...}, "cached_at": timestamp}}
        # Stores lookup results so we don't re-query the same domain
        self._cache = {}

        # Timestamp of the last API call (for rate limiting)
        self._last_call = 0

        # Whether threat intel is enabled (needs API key + requests library)
        self.enabled = bool(api_key and REQUESTS_AVAILABLE)

        if not REQUESTS_AVAILABLE:
            logger.warning(
                "requests library not installed. "
                "Install with: pip install requests"
            )
        if not api_key:
            logger.info(
                "No VirusTotal API key configured. "
                "Add 'virustotal_api_key' to config.json to enable."
            )

    def check_domain(self, domain):
        # Return a disabled result if not configured
        if not self.enabled:
            return self._disabled_result()

        # Clean the domain name
        domain = domain.rstrip(".").lower()

        # --- Step 1: Check local cache ---
        cached = self._get_from_cache(domain)
        if cached:
            return cached

        # --- Step 2: Rate limiting ---
        # Wait if we called the API less than RATE_LIMIT_SECS ago
        self._wait_for_rate_limit()

        # --- Step 3: Call VirusTotal API ---
        try:
            result = self._query_virustotal(domain)
            # Cache the result for CACHE_TTL seconds
            self._store_in_cache(domain, result)
            return result

        except Exception as e:
            logger.error(f"VirusTotal lookup failed for {domain}: {e}")
            return self._error_result(str(e))

    def _query_virustotal(self, domain):
        url = self.VT_URL.format(domain)

        # HTTP GET request to VirusTotal
        # headers: x-apikey authenticates us
        # timeout=10: don't wait more than 10 seconds for a response
        response = requests.get(
            url,
            headers={"x-apikey": self.api_key},
            timeout=10
        )

        # Record this API call time (for rate limiting)
        self._last_call = time.time()

        # HTTP 404 = domain not in VirusTotal's database (unknown, not clean)
        if response.status_code == 404:
            return {
                "malicious": False,
                "engines":   0,
                "harmless":  0,
                "source":    "virustotal",
                "url":       f"https://www.virustotal.com/gui/domain/{domain}",
                "note":      "Domain not in VirusTotal database",
                "error":     None,
            }

        # HTTP 429 = rate limit exceeded
        if response.status_code == 429:
            raise Exception("VirusTotal rate limit exceeded. Wait 1 minute.")

        # Any other non-200 status = API error
        response.raise_for_status()

        # Parse the JSON response body
        data = response.json()

        # Navigate the nested JSON structure to get the stats
        attrs  = data.get("data", {}).get("attributes", {})
        stats  = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)

        return {
            # True if ANY engine flagged it as malicious or suspicious
            "malicious": malicious > 0 or suspicious > 0,
            "engines":   malicious,       # how many said malicious
            "suspicious_engines": suspicious,
            "harmless":  harmless,        # how many said clean
            "source":    "virustotal",
            "url":       f"https://www.virustotal.com/gui/domain/{domain}",
            "error":     None,
        }

    def _get_from_cache(self, domain):
        """Returns cached result if it exists and hasn't expired."""
        if domain not in self._cache:
            return None

        entry = self._cache[domain]
        age = time.time() - entry["cached_at"]

        # Return cached result if it's less than CACHE_TTL seconds old
        if age < self.CACHE_TTL:
            entry["result"]["source"] = "cache"  # mark as from cache
            return entry["result"]

        # Cache expired — remove it
        del self._cache[domain]
        return None

    def _store_in_cache(self, domain, result):
        """Stores a result in the cache with a timestamp."""
        self._cache[domain] = {
            "result":    result,
            "cached_at": time.time(),
        }

    def _wait_for_rate_limit(self):
        """
        Waits if necessary to stay within the API rate limit.
        VirusTotal free tier: 4 requests per minute.
        We wait at least RATE_LIMIT_SECS between calls.
        """
        elapsed = time.time() - self._last_call
        if elapsed < self.RATE_LIMIT_SECS:
            wait_time = self.RATE_LIMIT_SECS - elapsed
            logger.debug(f"Rate limiting: waiting {wait_time:.1f}s")
            time.sleep(wait_time)

    def _disabled_result(self):
        return {
            "malicious": None,   # None = unknown (not checked)
            "engines":   0,
            "harmless":  0,
            "source":    "disabled",
            "url":       None,
            "error":     None,
        }

    def _error_result(self, message):
        return {
            "malicious": None,
            "engines":   0,
            "harmless":  0,
            "source":    "error",
            "url":       None,
            "error":     message,
        }

    def get_cache_stats(self):
        """Returns stats about the cache for display in the GUI."""
        return {
            "cached_domains":  len(self._cache),
            "enabled":         self.enabled,
            "api_key_set":     bool(self.api_key),
        }

    def clear_cache(self):
        """Clears the result cache (forces fresh lookups)."""
        self._cache.clear()
