"""
report_generator.py
--------------------
Final stage of the IAWM pipeline: takes everything already computed by
cve_parser.py, pattern_engine.py, risk_engine.py, and graph_engine.py
and produces a human-readable report (PDF or HTML) summarizing:

    - Executive summary (totals, top risky layers/CWEs)
    - Recurring architectural weakness patterns
    - Risk scores per layer/CWE
    - Link to the interactive knowledge graph (if generated)

Requires (for PDF export): reportlab
    pip install reportlab
"""

import datetime
from collections import defaultdict

import config
from database import IAWMDatabase

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
except ImportError:
    SimpleDocTemplate = None  # allows import without reportlab for HTML-only use


class ReportGenerator:

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

    def _load_risk_scores(self):
        columns = ["id", "component", "score"]
        rows = self.db.get_risk_scores()
        return [dict(zip(columns, row)) for row in rows]

    # =========================================================
    # Summary computation
    # =========================================================

    def build_summary(self):
        cves = self._load_cves()
        patterns = self._load_patterns()
        risk_scores = self._load_risk_scores()

        layer_counts = defaultdict(int)
        for cve in cves:
            layer_counts[cve["layer"] or "Unclassified"] += 1

        top_patterns = sorted(
            patterns, key=lambda p: p["occurrences"], reverse=True
        )[:10]

        top_risks = sorted(
            risk_scores, key=lambda r: r["score"], reverse=True
        )[:10]

        return {
            "total_cves": len(cves),
            "layer_counts": dict(layer_counts),
            "top_patterns": top_patterns,
            "top_risks": top_risks,
            "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        }

    # =========================================================
    # HTML export (always available, no extra dependency)
    # =========================================================

    def export_html(self, output_path=None):
        summary = self.build_summary()
        output_path = output_path or (config.REPORTS_DIR / "iawm_report.html")

        layer_rows = "".join(
            f"<tr><td>{layer}</td><td>{count}</td></tr>"
            for layer, count in summary["layer_counts"].items()
        )
        pattern_rows = "".join(
            f"<tr><td>{p['pattern_name']}</td><td>{p['occurrences']}</td>"
            f"<td>{p['risk_score']}</td></tr>"
            for p in summary["top_patterns"]
        )
        risk_rows = "".join(
            f"<tr><td>{r['component']}</td><td>{r['score']}</td></tr>"
            for r in summary["top_risks"]
        )

        html = f"""
        <html>
        <head>
            <meta charset="utf-8">
            <title>{config.REPORT_TITLE}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background:#0f0f0f; color:#eee; }}
                h1 {{ color: #e74c3c; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
                th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
                th {{ background-color: #1a1a1a; }}
            </style>
        </head>
        <body>
            <h1>{config.REPORT_TITLE}</h1>
            <p>Generated: {summary['generated_at']}</p>
            <p>Total CVEs analyzed: {summary['total_cves']}</p>

            <h2>CVEs per Layer</h2>
            <table><tr><th>Layer</th><th>Count</th></tr>{layer_rows}</table>

            <h2>Top Recurring Patterns</h2>
            <table><tr><th>Pattern</th><th>Occurrences</th><th>Risk Score</th></tr>{pattern_rows}</table>

            <h2>Top Risk Scores</h2>
            <table><tr><th>Component</th><th>Score</th></tr>{risk_rows}</table>

            <p>See the interactive knowledge graph: {config.GRAPH_OUTPUT_PATH.name}</p>
        </body>
        </html>
        """

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[*] HTML report written to: {output_path}")
        return output_path

    # =========================================================
    # PDF export (requires reportlab)
    # =========================================================

    def export_pdf(self, output_path=None):
        if SimpleDocTemplate is None:
            print("[!] reportlab is not installed. Run: pip install reportlab")
            return None

        summary = self.build_summary()
        output_path = output_path or (config.REPORTS_DIR / "iawm_report.pdf")

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#e74c3c")
        )

        doc = SimpleDocTemplate(str(output_path), pagesize=A4)
        elements = [
            Paragraph(config.REPORT_TITLE, title_style),
            Spacer(1, 0.5 * cm),
            Paragraph(f"Generated: {summary['generated_at']}", styles["Normal"]),
            Paragraph(f"Total CVEs analyzed: {summary['total_cves']}", styles["Normal"]),
            Spacer(1, 1 * cm),
            Paragraph("CVEs per Layer", styles["Heading2"]),
        ]

        layer_table_data = [["Layer", "Count"]] + [
            [layer, str(count)] for layer, count in summary["layer_counts"].items()
        ]
        elements.append(self._styled_table(layer_table_data))
        elements.append(Spacer(1, 1 * cm))

        elements.append(Paragraph("Top Recurring Patterns", styles["Heading2"]))
        pattern_table_data = [["Pattern", "Occurrences", "Risk Score"]] + [
            [p["pattern_name"], str(p["occurrences"]), str(p["risk_score"])]
            for p in summary["top_patterns"]
        ]
        elements.append(self._styled_table(pattern_table_data))
        elements.append(Spacer(1, 1 * cm))

        elements.append(Paragraph("Top Risk Scores", styles["Heading2"]))
        risk_table_data = [["Component", "Score"]] + [
            [r["component"], str(r["score"])] for r in summary["top_risks"]
        ]
        elements.append(self._styled_table(risk_table_data))

        doc.build(elements)
        print(f"[*] PDF report written to: {output_path}")
        return output_path

    def _styled_table(self, data):
        table = Table(data, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a1a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ]))
        return table

    # =========================================================
    # Pipeline
    # =========================================================

    def run(self, fmt=None):
        fmt = fmt or config.REPORT_DEFAULT_FORMAT
        if fmt == "pdf":
            return self.export_pdf()
        return self.export_html()


if __name__ == "__main__":
    generator = ReportGenerator()
    generator.run()