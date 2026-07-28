"""
config.py
---------
Central configuration file for IAWM (IPv6 Architectural Weakness Mapper).
All other modules (database.py, cve_parser.py, pattern_engine.py,
risk_engine.py, live_monitor.py, graph_engine.py, report_generator.py)
import their settings from here instead of hardcoding values.
"""

from pathlib import Path

# =============================================================
# Project paths
# =============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"

DB_PATH = DATA_DIR / "ipv6.db"

# Make sure required directories exist when config is imported
DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


# =============================================================
# NVD (National Vulnerability Database) settings
# =============================================================

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Keywords used to pull IPv6 / TCP related CVEs from NVD search
NVD_SEARCH_KEYWORDS = [
    "IPv6",
    "TCP/IP",
    "Neighbor Discovery",
    "ICMPv6",
    "Extension Header",
    "Fragmentation",
]

# NVD enforces stricter rate limits without an API key.
# If you have one, set it here (or load from an environment variable).
NVD_API_KEY = None  # e.g. os.environ.get("NVD_API_KEY")

# Delay (seconds) between consecutive NVD requests to respect rate limits
NVD_REQUEST_DELAY = 6 if NVD_API_KEY is None else 0.6

# Year range to collect CVEs for (matches your paper's scope)
CVE_YEAR_START = 2023
CVE_YEAR_END = 2025


# =============================================================
# Protocol layer classification
# =============================================================
# Used by cve_parser.py (NLP layer) to classify each CVE description
# into the architectural layer it affects.

PROTOCOL_LAYERS = {
    "Network Layer": ["ipv6", "routing header", "fragmentation", "extension header"],
    "Neighbor Discovery": ["ndp", "neighbor discovery", "router advertisement", "icmpv6"],
    "Transport Layer": ["tcp", "udp", "port", "segment", "handshake"],
    "Application Layer": ["dns", "http", "application", "service"],
}


# =============================================================
# CWE -> Attack phase mapping
# =============================================================
# Rough mapping used to tag which phase of an attack a CWE typically
# belongs to (recon, initial access, DoS, privilege escalation, etc.)

ATTACK_PHASE_MAP = {
    "CWE-400": "Denial of Service",
    "CWE-401": "Denial of Service",
    "CWE-404": "Denial of Service",
    "CWE-200": "Reconnaissance / Information Disclosure",
    "CWE-290": "Spoofing",
    # Add more CWE -> phase mappings here as you encounter them in the NVD data
}

DEFAULT_ATTACK_PHASE = "Uncategorized"


# =============================================================
# Risk scoring weights
# =============================================================
# Used by risk_engine.py to combine multiple signals into one score.
# Weights should sum to 1.0

RISK_WEIGHTS = {
    "cvss": 0.5,
    "pattern_frequency": 0.3,
    "layer_criticality": 0.2,
}

# How critical each layer is considered architecturally (0-1 scale)
LAYER_CRITICALITY = {
    "Network Layer": 0.9,
    "Neighbor Discovery": 0.85,
    "Transport Layer": 0.7,
    "Application Layer": 0.5,
}


# =============================================================
# Live packet monitoring (Scapy) settings
# =============================================================

DEFAULT_INTERFACE = "eth0"  # override per-machine, e.g. "wlan0" or "lo"
CAPTURE_FILTER = "ip6 or tcp"
CAPTURE_TIMEOUT = None  # None = capture indefinitely until stopped
CONFIDENCE_THRESHOLD = 0.6  # minimum confidence to log a packet as "matched"


# =============================================================
# Knowledge graph / visualization settings
# =============================================================

GRAPH_OUTPUT_PATH = REPORTS_DIR / "iawm_graph.html"
GRAPH_NODE_COLORS = {
    "cve": "#e74c3c",
    "layer": "#3498db",
    "cwe": "#f1c40f",
    "attack_phase": "#9b59b6",
}


# =============================================================
# Report generation settings
# =============================================================

REPORT_TITLE = "IPv6 Architectural Weakness Mapper (IAWM) Report"
REPORT_DEFAULT_FORMAT = "pdf"  # "pdf" or "html"