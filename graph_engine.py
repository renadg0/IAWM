"""
graph_engine.py
----------------
Builds the "Knowledge Graph + Visualization" layer of IAWM.

Nodes:
    - CVE nodes            (cve_id, sized/colored by risk)
    - Layer nodes          (Network Layer, Transport Layer, ...)
    - CWE nodes
    - Attack phase nodes

Edges connect each CVE to its layer, its CWE, and its attack phase, so
the resulting graph visually clusters CVEs that share an architectural
weakness — which is the whole point of IAWM: showing *repeated*
weaknesses, not just a flat CVE list.

Requires: networkx, pyvis
    pip install networkx pyvis
"""

import networkx as nx

import config
from database import IAWMDatabase

try:
    from pyvis.network import Network
except ImportError:
    Network = None  # allows import without pyvis for graph-building/testing only


class GraphEngine:

    def __init__(self):
        self.db = IAWMDatabase()
        self.graph = nx.Graph()

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

    def _load_risk_scores(self):
        """
        Returns a dict like:
            {"Layer: Network Layer": 0.81, "CWE: CWE-400": 0.6, ...}
        """
        rows = self.db.get_risk_scores()
        # columns: id, component, score
        return {row[1]: row[2] for row in rows}

    # =========================================================
    # Graph construction
    # =========================================================

    def build_graph(self):
        cves = self._load_cves()
        risk_scores = self._load_risk_scores()

        for cve in cves:
            cve_id = cve["cve_id"]
            layer = cve["layer"] or "Unclassified"
            cwe = cve["cwe"] or "Unknown CWE"
            phase = cve["attack_phase"] or config.DEFAULT_ATTACK_PHASE

            layer_risk = risk_scores.get(f"Layer: {layer}", 0.5)

            # --- CVE node ---
            self.graph.add_node(
                cve_id,
                node_type="cve",
                title=self._build_cve_tooltip(cve),
                color=config.GRAPH_NODE_COLORS["cve"],
                size=10 + (cve["cvss"] or 5) * 2,
            )

            # --- Layer node ---
            self.graph.add_node(
                layer,
                node_type="layer",
                title=f"Layer risk score: {layer_risk}",
                color=config.GRAPH_NODE_COLORS["layer"],
                size=25 + layer_risk * 20,
            )

            # --- CWE node ---
            self.graph.add_node(
                cwe,
                node_type="cwe",
                title=cwe,
                color=config.GRAPH_NODE_COLORS["cwe"],
                size=15,
            )

            # --- Attack phase node ---
            self.graph.add_node(
                phase,
                node_type="attack_phase",
                title=phase,
                color=config.GRAPH_NODE_COLORS["attack_phase"],
                size=15,
            )

            # --- Edges: CVE connects to layer, cwe, and phase ---
            self.graph.add_edge(cve_id, layer)
            self.graph.add_edge(cve_id, cwe)
            self.graph.add_edge(cve_id, phase)

        return self.graph

    def _build_cve_tooltip(self, cve):
        return (
            f"{cve['cve_id']}\n"
            f"CVSS: {cve['cvss']} ({cve['severity']})\n"
            f"CWE: {cve['cwe']}\n"
            f"Layer: {cve['layer']}\n"
            f"Year: {cve['year']}"
        )

    # =========================================================
    # Graph analysis helpers
    # =========================================================

    def most_connected_nodes(self, node_type=None, top_n=10):
        """
        Returns the top_n nodes by degree (connection count), optionally
        filtered by node_type ("layer", "cwe", "attack_phase", "cve").
        Useful for quickly spotting the most "central" architectural
        weaknesses without opening the visualization.
        """
        degrees = dict(self.graph.degree())

        if node_type:
            degrees = {
                n: d for n, d in degrees.items()
                if self.graph.nodes[n].get("node_type") == node_type
            }

        return sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:top_n]

    # =========================================================
    # Visualization export
    # =========================================================

    def export_html(self, output_path=None):
        if Network is None:
            print("[!] pyvis is not installed. Run: pip install pyvis")
            return None

        output_path = output_path or config.GRAPH_OUTPUT_PATH

        net = Network(height="800px", width="100%", bgcolor="#111111",
                       font_color="white", notebook=False)
        net.from_nx(self.graph)
        net.force_atlas_2based()

        net.write_html(str(output_path))
        print(f"[*] Knowledge graph written to: {output_path}")
        return output_path

    # =========================================================
    # Pipeline
    # =========================================================

    def run(self):
        self.build_graph()
        print(f"[*] Graph built: {self.graph.number_of_nodes()} nodes, "
              f"{self.graph.number_of_edges()} edges.")

        top_layers = self.most_connected_nodes(node_type="layer")
        print("\nMost connected layers:")
        for name, degree in top_layers:
            print(f"  {name}: {degree} connections")

        return self.export_html()


if __name__ == "__main__":
    engine = GraphEngine()
    engine.run()