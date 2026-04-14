import math    # for math.log2() used in Shannon entropy formula
import time    # for time.time() — current Unix timestamp
from collections import Counter   # counts character frequencies efficiently

# Scapy DNS layer — used to detect if a packet contains DNS data
# pyright: reportMissingImports=false
from scapy.all import DNS


# --- Constants used in feature calculations ----------------------------------

# All consonants in the English alphabet (lowercase)
# Used to calculate consonant_ratio — a strong signal for encoded subdomains
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

# All valid hexadecimal characters
# Used to detect if a subdomain looks like hex-encoded data
HEX_CHARS = set("0123456789abcdef")
def calculate_entropy(s):
    # Edge case: empty string has zero entropy (no information at all)
    if not s:
        return 0.0

    length = len(s)   # total number of characters

    # Counter() counts how many times each character appears
    # e.g. Counter("google") → {'g': 2, 'o': 2, 'l': 1, 'e': 1}
    counts = Counter(s)

    # Shannon formula: for each unique character, compute (p × log₂(p))
    # then sum them all and negate
    # p = count/length = probability of this character appearing
    # log₂(p) is always negative for 0 < p < 1, so negating gives positive H
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )

def extract_features(packet):

    # --- Step 1: Is this a DNS packet? ---
    # Scapy captures ALL network packets (HTTP, ICMP, DNS, etc.)
    # haslayer(DNS) asks: "does this packet contain a DNS layer?"
    # If not DNS, return None immediately — nothing to analyse
    if not packet.haslayer(DNS):
        return None

    # Extract the DNS layer from inside the packet
    # Think of it like peeling an onion: Ethernet > IP > UDP > DNS
    dns = packet[DNS]

    if dns.qd and dns.qr == 0:
        # This is a query packet — extract the domain being asked about
        query = dns.qd.qname.decode("utf-8").rstrip(".")
    else:
        # This is a response packet — no query name to extract
        query = ""

    # --- Step 3: Split domain into its parts ---
    # "mail.google.com" → ["mail", "google", "com"]
    # "agvsbg9xb3jsza.example.com" → ["agvsbg9xb3jsza", "example", "com"]
    parts = query.split(".") if query else []

    # The LEFTMOST label (parts[0]) is the most suspicious part.
    # In DNS tunneling, data is encoded here:
    #   "aGVsbG9Xb3JsZA.evil.com" → label = "aGVsbG9Xb3JsZA" (base64)
    # Normal domains have a readable word here:
    #   "mail.google.com" → label = "mail"
    label = parts[0].lower() if parts else ""

    # Avoid division by zero if label is empty
    lab_len = max(len(label), 1)

    # --- Step 4: Calculate the 5 new features (Phase 2 additions) ---

    # CONSONANT RATIO:
    # What fraction of the leftmost label's characters are consonants?
    # Normal words: ~50% consonants. Random base64: ~70-80% consonants.
    # e.g. "mail" → 3/4 = 0.75 | "aGVsbG9X" → mostly consonant-like chars
    consonant_ratio = (
        sum(1 for c in label if c in CONSONANTS) / lab_len
    )

    # NUMERIC RATIO:
    # What fraction of characters are digits?
    # Normal subdomains: 0–10% digits. Hex-encoded: 30–50% digits.
    # e.g. "mail" → 0/4 = 0.0 | "a3f9b2c1" → 4/8 = 0.5
    numeric_ratio = (
        sum(1 for c in label if c.isdigit()) / lab_len
    )

    unique_ratio = len(set(label)) / lab_len

    longest_label = max((len(p) for p in parts), default=0)

    has_hex = (
        1 if label and all(c in HEX_CHARS for c in label) else 0
    )

    ttl = dns.an.ttl if (dns.an and dns.qr == 1) else None

    return {
        "query":           query,          # domain name string
        "length":          len(query),     # total domain length in chars
        "entropy":         calculate_entropy(query),   # randomness score
        "subdomains":      len(parts) - 1 if query else 0,  # subdomain depth
        "consonant_ratio": consonant_ratio,  # fraction of consonants
        "numeric_ratio":   numeric_ratio,    # fraction of digits
        "unique_ratio":    unique_ratio,     # fraction of unique chars
        "longest_label":   longest_label,    # longest dot-separated segment
        "has_hex":         has_hex,          # 1 if hex-encoded, else 0
        "ttl":             ttl,             # None for queries, int for responses
        "timestamp":       time.time(),     # Unix timestamp of capture
    }
