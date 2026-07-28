"""
cve_parser.py
-------------
Fetches CVEs from the NVD API related to IPv6 / TCP, then runs a
lightweight NLP/keyword classification pass to tag each CVE with:
    - protocol layer      (Network / Neighbor Discovery / Transport / Application)
    - CWE                 (as reported by NVD)
    - attack phase         (via CWE -> phase mapping in config.py)
    - affected OS          (best-effort guess from the description text)

Results are pushed into the database via database.py (IAWMDatabase).
"""

import time
import re
import requests

import config
from database import IAWMDatabase


class CVEParser:

    def __init__(self):
        self.db = IAWMDatabase()

    # =========================================================
    # Fetching from NVD
    # =========================================================

    def fetch_cves_for_keyword(self, keyword, start_index=0, results_per_page=50):
        """
        Query the NVD 2.0 API for a single keyword.
        Returns the raw JSON response (dict) or None on failure.
        """
        params = {
            "keywordSearch": keyword,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }

        headers = {}
        if config.NVD_API_KEY:
            headers["apiKey"] = config.NVD_API_KEY

        try:
            response = requests.get(
                config.NVD_API_BASE_URL,
                params=params,
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"[!] NVD request failed for keyword '{keyword}': {e}")
            return None

    def fetch_all_keywords(self):
        """
        Loop over every keyword defined in config.NVD_SEARCH_KEYWORDS,
        respecting the configured rate-limit delay between calls.
        Returns a combined list of raw CVE items (deduplicated by CVE ID).
        """
        seen_ids = set()
        all_items = []

        for keyword in config.NVD_SEARCH_KEYWORDS:
            print(f"[*] Fetching CVEs for keyword: {keyword}")
            data = self.fetch_cves_for_keyword(keyword)

            if not data:
                continue

            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_id = item.get("cve", {}).get("id")
                if cve_id and cve_id not in seen_ids:
                    seen_ids.add(cve_id)
                    all_items.append(item)

            time.sleep(config.NVD_REQUEST_DELAY)

        print(f"[*] Total unique CVEs fetched: {len(all_items)}")
        return all_items

    # =========================================================
    # Parsing / extraction helpers
    # =========================================================

    def _extract_description(self, cve_item):
        descriptions = cve_item.get("cve", {}).get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                return d.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    def _extract_cvss(self, cve_item):
        """
        Returns (score, severity). Prefers CVSS v3.1, falls back to v3.0,
        then v2. Returns (None, None) if nothing is available.
        """
        metrics = cve_item.get("cve", {}).get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = (
                    metrics[key][0].get("baseSeverity")
                    or cvss_data.get("baseSeverity")
                )
                return score, severity

        return None, None

    def _extract_cwe(self, cve_item):
        weaknesses = cve_item.get("cve", {}).get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    return desc["value"]
        return None

    def _extract_year(self, cve_id):
        match = re.match(r"CVE-(\d{4})-", cve_id)
        return int(match.group(1)) if match else None

    # =========================================================
    # Classification (lightweight NLP / keyword matching)
    # =========================================================

    def classify_layer(self, description):
        """
        Keyword-based layer classification using config.PROTOCOL_LAYERS.
        Returns the first matching layer, or "Unclassified".
        """
        text = description.lower()

        for layer, keywords in config.PROTOCOL_LAYERS.items():
            for kw in keywords:
                if kw in text:
                    return layer

        return "Unclassified"

    def classify_attack_phase(self, cwe):
        if not cwe:
            return config.DEFAULT_ATTACK_PHASE
        return config.ATTACK_PHASE_MAP.get(cwe, config.DEFAULT_ATTACK_PHASE)

    def guess_os(self, description):
        """
        Best-effort OS detection from free text. Extend this list as
        you encounter more OS names in the CVE descriptions you collect.
        """
        text = description.lower()
        os_keywords = {
            "windows": "Windows",
            "linux": "Linux",
            "parrot os": "Parrot OS",
            "kali": "Kali Linux",
            "cisco ios": "Cisco IOS",
            "freebsd": "FreeBSD",
            "android": "Android",
        }

        for kw, label in os_keywords.items():
            if kw in text:
                return label

        return "Unknown"

    def extract_header(self, description):
        """
        Tries to spot a specific IPv6/TCP header mentioned in the text
        (e.g. 'Routing Header', 'Fragment Header', 'Hop-by-Hop').
        """
        known_headers = [
            "Routing Header",
            "Fragment Header",
            "Hop-by-Hop",
            "Destination Options",
            "Authentication Header",
            "TCP Options",
        ]

        for header in known_headers:
            if header.lower() in description.lower():
                return header

        return None

    # =========================================================
    # Pipeline: fetch -> parse -> classify -> store
    # =========================================================

    def process_and_store(self, cve_items):
        stored_count = 0

        for item in cve_items:
            cve_id = item.get("cve", {}).get("id")
            if not cve_id:
                continue

            description = self._extract_description(item)
            cvss, severity = self._extract_cvss(item)
            cwe = self._extract_cwe(item)
            year = self._extract_year(cve_id)

            layer = self.classify_layer(description)
            attack_phase = self.classify_attack_phase(cwe)
            os_guess = self.guess_os(description)
            header = self.extract_header(description)

            record = (
                cve_id,
                description,
                cvss,
                severity,
                cwe,
                layer,
                header,
                attack_phase,
                os_guess,
                year,
            )

            self.db.insert_cve(record)
            stored_count += 1

        print(f"[*] Stored/updated {stored_count} CVEs in the database.")
        return stored_count

    def run(self):
        """
        Full pipeline: fetch all configured keywords from NVD, then
        parse/classify/store each result.
        """
        items = self.fetch_all_keywords()

        # Optional: filter to the configured year range only
        filtered = []
        for item in items:
            year = self._extract_year(item.get("cve", {}).get("id", ""))
            if year and config.CVE_YEAR_START <= year <= config.CVE_YEAR_END:
                filtered.append(item)

        return self.process_and_store(filtered)


if __name__ == "__main__":
    parser = CVEParser()
    parser.run()