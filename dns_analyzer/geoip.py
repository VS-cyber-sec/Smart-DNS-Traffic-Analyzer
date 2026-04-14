import logging
import ipaddress   # built-in: validates and classifies IP addresses

logger = logging.getLogger(__name__)

# Try importing geoip2 — optional dependency
try:
    import geoip2.database  # pyright: ignore[reportMissingImports]
    import geoip2.errors  # pyright: ignore[reportMissingImports]
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False


class GeoIPLookup:
    def __init__(self, db_path="data/GeoLite2-City.mmdb"):
        """
        PARAMETERS:
            db_path = path to the GeoLite2-City.mmdb database file
        """
        self.db_path = db_path
        self.reader  = None    # geoip2 database reader object
        self.enabled = False

        if not GEOIP2_AVAILABLE:
            logger.warning(
                "geoip2 library not installed. "
                "Install with: pip install geoip2"
            )
            return

        # Try to open the database file
        try:
            # geoip2.database.Reader opens the .mmdb binary database
            # and keeps it in memory for fast repeated lookups
            self.reader  = geoip2.database.Reader(db_path)
            self.enabled = True
            logger.info(f"GeoIP database loaded from {db_path}")
        except FileNotFoundError:
            logger.warning(
                f"GeoIP database not found at {db_path}. "
                "Download GeoLite2-City.mmdb from maxmind.com"
            )
        except Exception as e:
            logger.error(f"Failed to open GeoIP database: {e}")

    def lookup(self, ip_address):
            # Default result (returned when lookup fails or is disabled)
        default = {
            "country_code": "??",
            "country_name": "Unknown",
            "city":         None,
            "latitude":     None,
            "longitude":    None,
            "is_private":   False,
            "error":        None,
        }

        if not ip_address:
            return {**default, "error": "No IP provided"}

        # --- Step 1: Check if this is a private/internal IP address ---
        # Private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x) are local
        # network addresses — they don't belong to any country.
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    **default,
                    "country_code": "LAN",
                    "country_name": "Local Network",
                    "is_private":   True,
                }
        except ValueError:
            return {**default, "error": f"Invalid IP: {ip_address}"}

        # --- Step 2: GeoIP lookup ---
        if not self.enabled:
            return {**default, "error": "GeoIP not configured"}

        try:
            # reader.city() queries the database for this IP
            # Returns a response object with country, city, location data
            response = self.reader.city(ip_address)

            return {
                # iso_code = 2-letter country code ("US", "DE", "RU", etc.)
                "country_code": response.country.iso_code or "??",
                "country_name": response.country.name or "Unknown",
                "city":         response.city.name,
                "latitude":     response.location.latitude,
                "longitude":    response.location.longitude,
                "is_private":   False,
                "error":        None,
            }

        except geoip2.errors.AddressNotFoundError:
            # IP not in the database (very rare, usually private ranges)
            return {**default, "error": "IP not in database"}
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
            return {**default, "error": str(e)}

    def extract_response_ips(self, dns_packet):
      
        # pyright: ignore[reportMissingImports]
        try:
            from scapy.all import DNSRR, DNSQR
        except ImportError:
            return []

        ips = []
        # dns.an = the "answer" section (a chain of DNS resource records)
        # We iterate through the chain using .payload
        record = dns_packet.an
        while record and record.type != 0:   # type 0 = end of chain
            # Record type 1 = A record (IPv4)
            # Record type 28 = AAAA record (IPv6)
            if record.type in (1, 28):
                if hasattr(record, "rdata"):
                    ips.append(str(record.rdata))
            try:
                # Move to the next record in the chain
                record = record.payload
                # Stop if we reach a non-DNSRR record
                if not hasattr(record, "type"):
                    break
            except Exception:
                break

        return ips

    def close(self):
        """Closes the database reader to free resources."""
        if self.reader:
            self.reader.close()
            self.reader  = None
            self.enabled = False


EXPECTED_REGIONS = {
    "google.com":    {"US", "IE", "NL", "BE", "DE", "SG", "TW"},
    "microsoft.com": {"US", "IE", "NL", "AT", "DE", "AU"},
    "apple.com":     {"US", "IE", "NL", "DE"},
    "amazon.com":    {"US", "IE", "DE", "LU"},
    "cloudflare.com":{"US", "GB", "DE", "AU", "SG"},
}


def is_geo_suspicious(domain, country_code, expected_regions=None):
   
    regions = expected_regions or EXPECTED_REGIONS

    # Check if the base domain (last 2 parts) has a rule
    parts = domain.rstrip(".").split(".")
    base  = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    if base in regions:
        # We have an expected region rule for this domain
        return country_code not in regions[base]

    # No rule for this domain — can't say it's suspicious based on geo
    return False
