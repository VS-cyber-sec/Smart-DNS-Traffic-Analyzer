# Smart DNS Traffic Analyzer 

## What this project does

Monitors all DNS traffic on your network in real time and detects:
- **DNS Tunneling** — data being smuggled inside DNS queries
- **DNS Spoofing** — forged DNS responses redirecting you to malicious IPs
- **Query Flooding** — same domain queried too many times (malware beaconing)
- **Statistical Anomalies** — unusual patterns that don't match any known attack
- **Known Malicious Domains** — confirmed bad domains via VirusTotal database

---

## Project structure

```bash
Smart-DNS-Traffic-Analyzer/
│
├── dns_analyzer/              
│   ├── __init__.py
│   ├── config.py              
│   ├── features.py            
│   ├── detection.py           
│   ├── lists.py               
│   ├── model.py               
│   ├── reporter.py            
│   ├── anomaly.py             
│   ├── threat_intel.py        
│   ├── geoip.py               
│   └── dashboard.py           
│
├── gui/
│   ├── __init__.py
│   └── app.py                 
│
├── tests/
│   ├── test_features.py       
│   └── test_detection.py      
│
├── data/
│   ├── allowlist.txt          
│   ├── blocklist.txt          
│   └── dns_model.pkl          
│
├── logs/                      
├── reports/                   
│
├── smart_dns_analyzer.py      
├── run_cli.py                 
├── train_model.py             
```
### Setup — step by step
```bash

### Step 1 — Install Npcap (Windows only)
Download from https://npcap.com and install with
"WinPcap API-compatible mode" checked.
```

### Step 2 — Install Python dependencies
```bash
pip install -r requirements.txt
pip install matplotlib         
pip install requests geoip2    
```

### Step 3 — Train the ML model (run once)
```bash
python train_model.py
```
Creates `data/dns_model.pkl`. Takes about 30 seconds.

### Step 4 — Configure 

**VirusTotal threat intelligence:**
1. Create free account at https://www.virustotal.com
2. Get your API key from your profile
3. Add to config.json:
```json
"virustotal_api_key": "your_key_here"
```

**Geo-IP lookup:**
GeoLite2-City.mmdb - file is in the /data folder but it need to update beacuse every week it will be updated

### Step 5 — Run

```bash
# GUI (recommended — needs admin/sudo for live capture)
python run_gui.py

# Command line
python run_cli.py

# Offline PCAP analysis (NO admin needed — great for testing)
python run_cli.py --pcap data/sample.pcap

# Run tests
pytest tests/ -v
```

---

## features explained simply

### Anomaly Detection (Isolation Forest)
Learns what "normal" DNS traffic looks like on YOUR network during
a warmup period (default 300 packets ≈ ~10 minutes). After warmup,
it automatically flags anything statistically unusual — even brand new
attack patterns it has never been trained to recognise.

### Threat Intelligence (VirusTotal)
When a domain is flagged as suspicious, your tool automatically checks
it against VirusTotal's database of 70+ antivirus engines. If multiple
engines confirm it's malicious, the status upgrades to "CONFIRMED MALICIOUS".
Free API key gives 500 lookups per day.

### Geo-IP Lookup (MaxMind GeoLite2)
When a DNS response arrives, it checks which country the resolved IP
belongs to. If google.com suddenly resolves to a Russian or Chinese IP,
that's a strong sign of DNS cache poisoning and gets flagged immediately.

### Unit Tests + CI
pytest tests in `tests/` verify every detection function works correctly.
GitHub Actions runs them automatically on every code push so you always
know within 2 minutes if your changes broke anything.

### Live Dashboard (matplotlib)
The GUI now has a Dashboard tab with live-updating bar charts showing
packet status breakdown, a threat rate timeline, and the anomaly
detector's warmup progress.

---

## Running the tests

```bash
# Install pytest
pip install pytest

# Run all tests
pytest tests/ -v

# Run with coverage report
pip install pytest-cov
pytest tests/ -v --cov=dns_analyzer

# Run just one test file
pytest tests/test_features.py -v

# Run just one specific test
pytest tests/test_features.py::TestCalculateEntropy::test_empty_string_returns_zero -v
```
If you used any DNS repeated then add that in the allowlist so it doesnot flag as suspicious
