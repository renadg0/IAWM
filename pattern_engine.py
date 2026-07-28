"""
pattern_engine.py
------------------
Analyzes the CVEs already stored in the database (via cve_parser.py) to
find recurring architectural weakness patterns in IPv6/TCP:
    - which (layer, CWE) combinations repeat most often
    - which specific headers keep showing up across different CVEs/years
    - which attack phases dominate for each layer

Each detected pattern is scored for "risk" (a simple frequency-weighted
score for now — risk_engine.py later combines this with CVSS and layer
criticality for the final risk score) and stored via database.py.
"""

from collections import Counter, defaultdict

import config
from database import IAWMDatabase


class PatternEngine:

    def __init__(self):
        self.db = IAWMDatabase()

    # =========================================================
    # Data loading
    # =========================================================

    def _load_cves(self):
        """
        Returns the raw rows from the cves table as a list of dicts,
        using the same column order as database.py's create_tables().
        """
        columns = [
            "id", "cve_id", "description", "cvss", "severity",
            "cwe", "layer", "header", "attack_phase", "os", "year",
        ]
        rows = self.db.get_all_cves()
        return [dict(zip(columns, row)) for row in rows]

    # =========================================================
    # Pattern detection
    # =========================================================

    def find_layer_cwe_patterns(self, cves):
        """
        Counts how often each (layer, cwe) combination occurs.
        Returns a Counter keyed by "layer | cwe".
        """
        counter = Counter()
        for cve in cves:
            layer = cve["layer"] or "Unclassified"
            cwe = cve["cwe"] or "Unknown CWE"
            counter[f"{layer} | {cwe}"] += 1
        return counter

    def find_header_patterns(self, cves):
        """
        Counts how often each specific IPv6/TCP header is implicated
        across CVEs (only counts CVEs where a header was detected).
        """
        counter = Counter()
        for cve in cves:
            if cve["header"]:
                counter[cve["header"]] += 1
        return counter

    def find_attack_phase_distribution(self, cves):
        """
        For each layer, counts the distribution of attack phases.
        Returns {layer: Counter({phase: count})}
        """
        distribution = defaultdict(Counter)
        for cve in cves:
            layer = cve["layer"] or "Unclassified"
            phase = cve["attack_phase"] or config.DEFAULT_ATTACK_PHASE
            distribution[layer][phase] += 1
        return distribution

    def find_os_patterns(self, cves):
        """
        Counts how often each OS shows up as affected across CVEs.
        """
        counter = Counter()
        for cve in cves:
            counter[cve["os"] or "Unknown"] += 1
        return counter

    def find_yearly_trend(self, cves):
        """
        Counts CVEs per year per layer, useful for spotting whether a
        given architectural weakness is trending up or down over time.
        Returns {layer: {year: count}}
        """
        trend = defaultdict(lambda: defaultdict(int))
        for cve in cves:
            if cve["year"]:
                layer = cve["layer"] or "Unclassified"
                trend[layer][cve["year"]] += 1
        return trend

    # =========================================================
    # Simple frequency-based risk score for a pattern
    # =========================================================

    def _pattern_risk_score(self, occurrences, total_cves):
        """
        A simple normalized frequency score (0-1). risk_engine.py will
        later combine this with CVSS/layer criticality for the final
        component risk score — this is just the "how repetitive is this
        weakness" signal.
        """
        if total_cves == 0:
            return 0.0
        return round(occurrences / total_cves, 4)

    # =========================================================
    # Pipeline: analyze -> store
    # =========================================================

    def run(self):
        cves = self._load_cves()
        total = len(cves)

        if total == 0:
            print("[!] No CVEs found in the database. Run cve_parser.py first.")
            return

        layer_cwe_patterns = self.find_layer_cwe_patterns(cves)
        header_patterns = self.find_header_patterns(cves)
        phase_distribution = self.find_attack_phase_distribution(cves)
        os_patterns = self.find_os_patterns(cves)
        yearly_trend = self.find_yearly_trend(cves)

        # Store layer|cwe patterns (the core architectural weakness patterns)
        for pattern_name, occurrences in layer_cwe_patterns.items():
            risk = self._pattern_risk_score(occurrences, total)
            self.db.insert_pattern(pattern_name, occurrences, risk)

        # Store header-level patterns too (e.g. "Header: Routing Header")
        for header, occurrences in header_patterns.items():
            risk = self._pattern_risk_score(occurrences, total)
            self.db.insert_pattern(f"Header: {header}", occurrences, risk)

        print(f"[*] Analyzed {total} CVEs.")
        print(f"[*] Found {len(layer_cwe_patterns)} layer/CWE patterns.")
        print(f"[*] Found {len(header_patterns)} recurring header patterns.")

        return {
            "layer_cwe_patterns": layer_cwe_patterns,
            "header_patterns": header_patterns,
            "phase_distribution": phase_distribution,
            "os_patterns": os_patterns,
            "yearly_trend": yearly_trend,
        }


if __name__ == "__main__":
    engine = PatternEngine()
    results = engine.run()

    if results:
        print("\nTop layer/CWE patterns:")
        for name, count in results["layer_cwe_patterns"].most_common(5):
            print(f"  {name}: {count}")