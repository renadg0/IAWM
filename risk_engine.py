"""
risk_engine.py
--------------
Combines multiple signals into a single "architectural risk score" per
component (protocol layer, CWE, header, etc.):

    final_score = (cvss_norm      * RISK_WEIGHTS["cvss"])
                + (pattern_freq   * RISK_WEIGHTS["pattern_frequency"])
                + (layer_crit     * RISK_WEIGHTS["layer_criticality"])

This is the "Risk Scoring Engine" box in the IAWM architecture diagram —
it sits between pattern_engine.py (frequency signal) and
graph_engine.py / report_generator.py (which consume the final scores).

Final scores are stored in the risk_scores table via database.py.
"""

from collections import defaultdict

import config
from database import IAWMDatabase


class RiskEngine:

    def __init__(self):
        self.db = IAWMDatabase()

    # =========================================================
    # Data loading
    # =========================================================

    def _load_cves(self):
        columns = [
            "id", "cve_id", "description", "cvss", "severity",
            "cwe", "layer", "header", "attack_phase", "os", "year",
        ]
        rows = self.db.get_all_cves()
        return [dict(zip(columns, row)) for row in rows]

    def _load_patterns(self):
        columns = ["id", "pattern_name", "occurrences", "risk_score"]
        rows = self.db.get_patterns()
        return [dict(zip(columns, row)) for row in rows]

    # =========================================================
    # Normalization helpers
    # =========================================================

    def _normalize_cvss(self, cvss):
        """
        NVD CVSS scores range 0-10. Normalize to 0-1.
        Missing scores are treated as a neutral 0.5 rather than 0,
        so a CVE with no CVSS data doesn't look artificially "safe".
        """
        if cvss is None:
            return 0.5
        return max(0.0, min(cvss / 10.0, 1.0))

    def _layer_criticality(self, layer):
        return config.LAYER_CRITICALITY.get(layer, 0.5)

    # =========================================================
    # Per-layer aggregation
    # =========================================================

    def compute_layer_scores(self, cves):
        """
        Groups CVEs by layer, averages their normalized CVSS, and
        combines it with the layer's fixed criticality and the
        pattern-frequency signal (share of total CVEs in that layer)
        to produce one final score per layer.
        """
        by_layer = defaultdict(list)
        for cve in cves:
            layer = cve["layer"] or "Unclassified"
            by_layer[layer].append(cve)

        total_cves = len(cves) or 1
        scores = {}

        for layer, layer_cves in by_layer.items():
            avg_cvss_norm = sum(
                self._normalize_cvss(c["cvss"]) for c in layer_cves
            ) / len(layer_cves)

            pattern_freq = len(layer_cves) / total_cves
            layer_crit = self._layer_criticality(layer)

            final_score = (
                avg_cvss_norm * config.RISK_WEIGHTS["cvss"]
                + pattern_freq * config.RISK_WEIGHTS["pattern_frequency"]
                + layer_crit * config.RISK_WEIGHTS["layer_criticality"]
            )

            scores[layer] = round(final_score, 4)

        return scores

    # =========================================================
    # Per-CWE aggregation (finer granularity than layer)
    # =========================================================

    def compute_cwe_scores(self, cves):
        by_cwe = defaultdict(list)
        for cve in cves:
            cwe = cve["cwe"] or "Unknown CWE"
            by_cwe[cwe].append(cve)

        total_cves = len(cves) or 1
        scores = {}

        for cwe, cwe_cves in by_cwe.items():
            avg_cvss_norm = sum(
                self._normalize_cvss(c["cvss"]) for c in cwe_cves
            ) / len(cwe_cves)

            pattern_freq = len(cwe_cves) / total_cves

            # A CWE isn't tied to one layer, so use the average
            # criticality of the layers it appears in.
            layers_involved = {c["layer"] or "Unclassified" for c in cwe_cves}
            avg_layer_crit = sum(
                self._layer_criticality(l) for l in layers_involved
            ) / len(layers_involved)

            final_score = (
                avg_cvss_norm * config.RISK_WEIGHTS["cvss"]
                + pattern_freq * config.RISK_WEIGHTS["pattern_frequency"]
                + avg_layer_crit * config.RISK_WEIGHTS["layer_criticality"]
            )

            scores[cwe] = round(final_score, 4)

        return scores

    # =========================================================
    # Pipeline: compute -> store
    # =========================================================

    def run(self):
        cves = self._load_cves()

        if not cves:
            print("[!] No CVEs found in the database. Run cve_parser.py first.")
            return

        layer_scores = self.compute_layer_scores(cves)
        cwe_scores = self.compute_cwe_scores(cves)

        for layer, score in layer_scores.items():
            self.db.update_risk(f"Layer: {layer}", score)

        for cwe, score in cwe_scores.items():
            self.db.update_risk(f"CWE: {cwe}", score)

        print(f"[*] Computed risk scores for {len(layer_scores)} layers "
              f"and {len(cwe_scores)} CWEs.")

        return {"layer_scores": layer_scores, "cwe_scores": cwe_scores}


if __name__ == "__main__":
    engine = RiskEngine()
    results = engine.run()

    if results:
        print("\nLayer risk scores (highest first):")
        for layer, score in sorted(
            results["layer_scores"].items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {layer}: {score}")