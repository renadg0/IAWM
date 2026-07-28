"""
main.py
-------
Entry point for IAWM (IPv6 Architectural Weakness Mapper).

Runs the full pipeline shown in the architecture diagram:

    NVD CVEs -> NLP Parser -> (Layer / CWE / Attack Phase)
             -> Risk Scoring Engine
             -> Knowledge Graph + Visualization
             -> Live Packet Correlation (optional, separate mode)

Usage:
    python main.py                further collect+analyze+report (default)
    python main.py --skip-fetch   re-run analysis/report on existing DB data
    python main.py --monitor      only run the live packet monitor
    python main.py --report-only  only (re)generate the report + graph
"""

import argparse

import config
from cve_parser import CVEParser
from pattern_engine import PatternEngine
from risk_engine import RiskEngine
from graph_engine import GraphEngine
from report_generator import ReportGenerator
from live_monitor import LiveMonitor


def run_pipeline(skip_fetch=False):
    print("=" * 60)
    print(" IAWM - IPv6 Architectural Weakness Mapper")
    print("=" * 60)

    if not skip_fetch:
        print("\n[1/4] Fetching & classifying CVEs from NVD...")
        CVEParser().run()
    else:
        print("\n[1/4] Skipping NVD fetch (using existing database data).")

    print("\n[2/4] Detecting recurring architectural patterns...")
    PatternEngine().run()

    print("\n[3/4] Computing risk scores...")
    RiskEngine().run()

    print("\n[4/4] Building knowledge graph & generating report...")
    GraphEngine().run()
    ReportGenerator().run()

    print("\n[*] Pipeline complete.")
    print(f"[*] Reports available under: {config.REPORTS_DIR}")


def run_report_only():
    print("[*] Regenerating knowledge graph and report from existing data...")
    GraphEngine().run()
    ReportGenerator().run()


def run_monitor():
    print("[*] Starting live packet monitor (Ctrl+C to stop)...")
    LiveMonitor().start()


def parse_args():
    parser = argparse.ArgumentParser(
        description="IAWM - IPv6 Architectural Weakness Mapper"
    )
    parser.add_argument(
        "--skip-fetch", action="store_true",
        help="Skip fetching new CVEs from NVD; analyze existing DB data only.",
    )
    parser.add_argument(
        "--monitor", action="store_true",
        help="Run only the live Scapy packet monitor.",
    )
    parser.add_argument(
        "--report-only", action="store_true",
        help="Only (re)generate the knowledge graph and report.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.monitor:
        run_monitor()
    elif args.report_only:
        run_report_only()
    else:
        run_pipeline(skip_fetch=args.skip_fetch)