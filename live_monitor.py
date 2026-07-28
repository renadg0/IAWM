"""
live_monitor.py
----------------
Live packet correlation layer ("Live Packet Correlation (Scapy)" box in
the IAWM architecture diagram).

Captures live traffic with Scapy, extracts IPv6/TCP header features from
each packet, and checks them against the patterns already discovered by
pattern_engine.py (stored in the `patterns` table) to flag packets that
resemble a known architectural weakness pattern.

Matches are logged to the packet_logs table via database.py.

NOTE: Requires root/administrator privileges to sniff traffic.
NOTE: This module is for detection/monitoring only — it inspects and
      logs traffic, it does not send, forge, or replay any packets.
"""

import datetime

import config
from database import IAWMDatabase

try:
    from scapy.all import sniff, IPv6, TCP, ICMPv6ND_NS, ICMPv6ND_RA
except ImportError:
    sniff = None  # allows the module to be imported for testing without scapy


class LiveMonitor:

    def __init__(self):
        self.db = IAWMDatabase()
        self.known_patterns = self._load_known_patterns()

    # =========================================================
    # Load known patterns from the DB so we know what to look for
    # =========================================================

    def _load_known_patterns(self):
        """
        Returns a simple list of pattern name strings (e.g.
        "Network Layer | CWE-400", "Header: Fragment Header") that
        pattern_engine.py has already identified as recurring.
        """
        rows = self.db.get_patterns()
        # columns: id, pattern_name, occurrences, risk_score
        return [row[1] for row in rows]

    # =========================================================
    # Feature extraction from a single packet
    # =========================================================

    def _extract_features(self, packet):
        """
        Pulls the relevant IPv6/TCP header fields out of a packet.
        Returns a dict, or None if the packet isn't IPv6.
        """
        if not packet.haslayer(IPv6):
            return None

        ipv6_layer = packet[IPv6]

        features = {
            "src_ip": ipv6_layer.src,
            "dst_ip": ipv6_layer.dst,
            "next_header": ipv6_layer.nh,
            "has_fragment": packet.haslayer("IPv6ExtHdrFragment"),
            "has_routing_header": packet.haslayer("IPv6ExtHdrRouting"),
            "has_hop_by_hop": packet.haslayer("IPv6ExtHdrHopByHop"),
            "has_tcp": packet.haslayer(TCP),
            "has_nd": packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_RA),
        }

        if features["has_tcp"]:
            tcp_layer = packet[TCP]
            features["tcp_flags"] = str(tcp_layer.flags)
            features["tcp_options"] = tcp_layer.options

        return features

    # =========================================================
    # Matching against known patterns (heuristic, extensible)
    # =========================================================

    def _match_pattern(self, features):
        """
        Very lightweight heuristic matcher: maps observed header
        combinations to a pattern label + confidence score. Extend this
        as your CVE/pattern research uncovers more specific signatures.

        Returns (pattern_label, confidence) or (None, 0.0) if nothing matches.
        """
        if features["has_routing_header"]:
            return "Network Layer | Routing Header anomaly", 0.7

        if features["has_fragment"]:
            return "Network Layer | Fragmentation anomaly", 0.7

        if features["has_nd"]:
            return "Neighbor Discovery | NDP anomaly", 0.6

        if features["has_tcp"] and "tcp_flags" in features:
            # Example heuristic: unusual flag combos worth flagging for review
            suspicious_flag_combos = {"FPU", "SF", "SFR"}
            if features["tcp_flags"] in suspicious_flag_combos:
                return "Transport Layer | Suspicious TCP flag combination", 0.5

        return None, 0.0

    # =========================================================
    # Per-packet callback (used by scapy.sniff)
    # =========================================================

    def _handle_packet(self, packet):
        features = self._extract_features(packet)
        if not features:
            return

        pattern_label, confidence = self._match_pattern(features)

        if pattern_label and confidence >= config.CONFIDENCE_THRESHOLD:
            timestamp = datetime.datetime.now().isoformat()
            headers_summary = (
                f"next_header={features['next_header']}, "
                f"routing={features['has_routing_header']}, "
                f"fragment={features['has_fragment']}, "
                f"hop_by_hop={features['has_hop_by_hop']}"
            )

            record = (
                timestamp,
                features["src_ip"],
                features["dst_ip"],
                "TCP" if features["has_tcp"] else "IPv6",
                headers_summary,
                pattern_label,
                confidence,
            )

            self.db.insert_packet(record)
            print(f"[MATCH] {timestamp} | {features['src_ip']} -> "
                  f"{features['dst_ip']} | {pattern_label} "
                  f"(confidence={confidence})")

    # =========================================================
    # Entry point
    # =========================================================

    def start(self, interface=None, packet_count=0):
        """
        Starts sniffing. packet_count=0 means capture indefinitely
        (until interrupted with Ctrl+C).
        """
        if sniff is None:
            print("[!] scapy is not installed. Run: pip install scapy")
            return

        iface = interface or config.DEFAULT_INTERFACE
        print(f"[*] Starting live monitor on interface: {iface}")
        print(f"[*] Filter: {config.CAPTURE_FILTER}")
        print(f"[*] Loaded {len(self.known_patterns)} known patterns for reference.")

        sniff(
            iface=iface,
            filter=config.CAPTURE_FILTER,
            prn=self._handle_packet,
            store=False,
            count=packet_count,
            timeout=config.CAPTURE_TIMEOUT,
        )


if __name__ == "__main__":
    monitor = LiveMonitor()
    monitor.start()