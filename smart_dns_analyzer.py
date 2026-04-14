# pyright: reportMissingImports=false
import logging
import time
from collections import defaultdict

from colorama import init, Fore, Style
from scapy.all import DNS

# Phase 3 modules
from dns_analyzer.config    import load_config
from dns_analyzer.features  import extract_features, calculate_entropy
from dns_analyzer.detection import FrequencyTracker, SpoofingDetector
from dns_analyzer.lists     import load_list, is_match
from dns_analyzer.model     import load_or_train_model, predict as ml_predict

# Phase 5 modules
from dns_analyzer.anomaly      import AnomalyDetector
from dns_analyzer.threat_intel import ThreatIntelChecker
from dns_analyzer.geoip        import GeoIPLookup, is_geo_suspicious

# Cross-platform audio
try:
    import winsound
    def play_beep(freq, duration):
        winsound.Beep(freq, duration)
except ImportError:
    try:
        import beepy
        def play_beep(freq, duration):
            beepy.beep(sound="ping")
    except ImportError:
        def play_beep(freq, duration):
            pass   # silent fallback

init()   # activate colorama


class SmartDNSAnalyzer:
    """
    Core DNS analysis engine — Phase 5 complete version.
    All detection subsystems are composed here.
    """

    def __init__(self, cfg=None, config_path="config.json"):
        """
        PARAMETERS:
            cfg         = pre-loaded config dict (optional)
            config_path = path to config.json (used if cfg not provided)
        """
        # --- Load configuration ---
        self.cfg = cfg if cfg is not None else load_config(config_path)

        # --- Set up logging ---
        os.makedirs(os.path.dirname(
            self.cfg.get("log_file", "logs/dns_threats.log")),
            exist_ok=True)
        logging.basicConfig(
            filename=self.cfg["log_file"],
            level=logging.INFO,
            format="%(asctime)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

        # --- Thresholds (read from config) ---
        self.entropy_threshold  = self.cfg["entropy_threshold"]
        self.length_threshold   = self.cfg["length_threshold"]
        self.ttl_low_threshold  = self.cfg["ttl_low_threshold"]
        self.ttl_high_threshold = self.cfg["ttl_high_threshold"]
        self.freq_threshold     = self.cfg["freq_threshold"]

        # --- Phase 3: Core detection subsystems ---
        # ML model: RandomForest (loaded from disk or trained fallback)
        self.model = load_or_train_model(self.cfg.get("model_path"))

        # Frequency tracker: sliding window query counter
        self.freq_tracker = FrequencyTracker(
            window_secs=self.cfg.get("freq_window_secs", 10))

        # Spoofing detector: TTL anomaly + transaction ID tracking
        self.spoof_detector = SpoofingDetector(
            ttl_low=self.ttl_low_threshold,
            ttl_high=self.ttl_high_threshold,
        )

        # Allow/blocklist: wildcard pattern matching
        self.allowlist = load_list(self.cfg.get("allowlist_path",
                                                "data/allowlist.txt"))
        self.blocklist = load_list(self.cfg.get("blocklist_path",
                                                "data/blocklist.txt"))

        # Last reload timestamp (for auto-reload feature)
        self._last_list_reload = time.time()

        # --- Phase 5: Advanced subsystems ---

        # Anomaly detector: Isolation Forest (unsupervised)
        # Detects unknown attack patterns after a warmup period
        self.anomaly_detector = AnomalyDetector(
            warmup=self.cfg.get("anomaly_warmup", 300),
            contamination=self.cfg.get("anomaly_contamination", 0.05),
        )

        # Threat intelligence: VirusTotal API lookup
        # Only enabled if an API key is configured
        self.threat_intel = ThreatIntelChecker(
            api_key=self.cfg.get("virustotal_api_key", None)
        )

        # Geo-IP lookup: maps response IPs to countries
        self.geoip = GeoIPLookup(
            db_path=self.cfg.get("geoip_db_path", "data/GeoLite2-City.mmdb")
        )

        print(Fore.GREEN + "[SmartDNSAnalyzer] Initialized" + Style.RESET_ALL)
        if self.threat_intel.enabled:
            print(Fore.GREEN +
                  "[SmartDNSAnalyzer] Threat intelligence: ENABLED" +
                  Style.RESET_ALL)
        if self.geoip.enabled:
            print(Fore.GREEN +
                  "[SmartDNSAnalyzer] Geo-IP lookup: ENABLED" +
                  Style.RESET_ALL)

    def extract_features(self, packet):
        """Delegates to the features module."""
        return extract_features(packet)

    def predict(self, features):
        """
        Runs the ML model to classify a domain as Normal or Tunneling.
        Returns (label, confidence) tuple.
        """
        return ml_predict(
            self.model, features,
            entropy_threshold=self.entropy_threshold,
            length_threshold=self.length_threshold,
        )

    def _maybe_reload_lists(self):
        """
        Auto-reloads allowlist and blocklist from disk every 30 seconds.
        This lets you add domains to the allowlist without restarting.
        """
        if not self.cfg.get("auto_allowlist_reload", True):
            return
        now = time.time()
        interval = self.cfg.get("reload_interval_secs", 30)
        if now - self._last_list_reload > interval:
            self.allowlist = load_list(
                self.cfg.get("allowlist_path", "data/allowlist.txt"))
            self.blocklist = load_list(
                self.cfg.get("blocklist_path", "data/blocklist.txt"))
            self._last_list_reload = now

    def dns_monitor(self, packet):
        """
        Main packet handler — called by Scapy for every DNS packet.
        Runs the full Phase 5 detection pipeline.
        """
        # Auto-reload lists periodically
        self._maybe_reload_lists()

        # Step 1: Extract features
        features = self.extract_features(packet)
        if not features:
            return

        dns = packet[DNS]

        # Step 2: Branch on query vs response
        if features["query"]:
            # ---- QUERY PACKET ----
            query = features["query"]

            # Record transaction ID for spoofing detection
            self.spoof_detector.record_query(dns)

            # ML classification
            ml_result, confidence = self.predict(features)

            # Frequency count
            freq = self.freq_tracker.get_frequency(query)

            # Phase 5: Anomaly detection score
            is_anomaly, anomaly_score = self.anomaly_detector.score(features)

            spoofed, spoof_reason = False, "none"
            geo_info = None

        else:
            # ---- RESPONSE PACKET ----
            query = ""

            # Spoofing check (TTL + transaction ID)
            spoofed, spoof_reason = self.spoof_detector.check_response(dns)

            ml_result, confidence = None, 0
            freq = 0
            is_anomaly, anomaly_score = False, 0.0

            # Phase 5: Geo-IP lookup on response IPs
            if self.geoip.enabled:
                ips = self.geoip.extract_response_ips(dns)
                if ips:
                    geo_info = self.geoip.lookup(ips[0])
                    # Check if geo is suspicious for this domain
                    if (geo_info.get("country_code") and
                            is_geo_suspicious(
                                features.get("query", ""),
                                geo_info["country_code"])):
                        spoofed      = True
                        spoof_reason = (f"geo_mismatch "
                                        f"({geo_info['country_code']})")
                else:
                    geo_info = None
            else:
                geo_info = None

        # Step 3: Allow/blocklist check
        allowlisted, allow_pat = is_match(query, self.allowlist)
        blocklisted, block_pat = is_match(query, self.blocklist)

        # Step 4: Determine final status (priority order)
        if allowlisted:
            status = f"Normal (Allowlisted: {allow_pat})"
            color  = Fore.WHITE
            tag    = "normal"

        elif blocklisted:
            status = f"Blocked ({block_pat})"
            color  = Fore.RED
            tag    = "spoofing"
            if self.cfg.get("alert_sound"):
                play_beep(1500, 300)

        elif spoofed:
            status = f"Spoofing Detected ({spoof_reason})"
            color  = Fore.RED
            tag    = "spoofing"
            if self.cfg.get("alert_sound"):
                play_beep(1500, 300)

        elif ml_result == "Tunneling" or freq > self.freq_threshold:
            status = (f"Suspicious — ML:{confidence:.0%} "
                      f"Freq:{freq}")
            color  = Fore.YELLOW
            tag    = "suspicious"
            if self.cfg.get("alert_sound"):
                play_beep(1000, 200)

        elif is_anomaly:
            # Phase 5: Isolation Forest flagged this as statistically unusual
            status = f"Anomaly Detected (score: {anomaly_score:.2f})"
            color  = Fore.YELLOW
            tag    = "suspicious"

        else:
            status = "Normal"
            color  = Fore.WHITE
            tag    = "normal"

        # Step 5: Phase 5 — Threat intelligence lookup for suspicious domains
        # Only query VT for suspicious/spoofing (not normal — saves API quota)
        vt_result = None
        if tag in ("suspicious", "spoofing") and query and self.threat_intel.enabled:
            vt_result = self.threat_intel.check_domain(query)
            if vt_result.get("malicious"):
                status = (f"CONFIRMED MALICIOUS "
                          f"({vt_result['engines']} engines)")
                color  = Fore.RED
                tag    = "spoofing"

        # Step 6: Build and print the output block
        block_lines = [
            f"DNS Query  : {query or '(response)'}",
            f"Status     : {status}",
            f"Entropy    : {features['entropy']:.3f}  "
            f"Length: {features['length']}  "
            f"Subdomains: {features['subdomains']}",
            f"Freq (10s) : {freq}  "
            f"TTL: {features['ttl']}",
        ]

        if anomaly_score > 0:
            block_lines.append(
                f"Anomaly    : {anomaly_score:.3f} "
                f"({'flagged' if is_anomaly else 'normal'})"
            )

        if geo_info and geo_info.get("country_code"):
            block_lines.append(
                f"Geo-IP     : {geo_info['country_code']} "
                f"({geo_info.get('city') or 'unknown city'})"
            )

        if vt_result and vt_result.get("engines"):
            block_lines.append(
                f"VirusTotal : {vt_result['engines']} engines flagged  "
                f"{vt_result.get('url', '')}"
            )

        block_lines.append("─" * 60)

        print(color + "\n".join(block_lines) + Style.RESET_ALL)
        self.logger.info("\n".join(block_lines))


# Allow this to be imported without os import error
import os
