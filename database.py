import sqlite3
from pathlib import Path


class IAWMDatabase:

    def __init__(self):
        Path("data").mkdir(exist_ok=True)
        self.db_path = "data/ipv6.db"
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.create_tables()


    def create_tables(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE,
            description TEXT,
            cvss REAL,
            severity TEXT,
            cwe TEXT,
            layer TEXT,
            header TEXT,
            attack_phase TEXT,
            os TEXT,
            year INTEGER
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS patterns(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_name TEXT,
            occurrences INTEGER,
            risk_score REAL
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            headers TEXT,
            matched_pattern TEXT,
            confidence REAL
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_scores(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component TEXT UNIQUE,
            score REAL
        )
        """)

        self.conn.commit()


    ###############################################################


    def insert_cve(self, data):
        self.cursor.execute("""
        INSERT OR IGNORE INTO cves(
        cve_id,
        description,
        cvss,
        severity,
        cwe,
        layer,
        header,
        attack_phase,
        os,
        year
        )
        VALUES(?,?,?,?,?,?,?,?,?,?)
        """, data)
        self.conn.commit()


    ###############################################################


    def insert_pattern(self, name, occurrences, risk):
        self.cursor.execute("""
        INSERT INTO patterns(
        pattern_name,
        occurrences,
        risk_score
        )
        VALUES(?,?,?)
        """,(name,occurrences,risk))
        self.conn.commit()


    ###############################################################


    def insert_packet(self,data):
        self.cursor.execute("""
        INSERT INTO packet_logs(
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        headers,
        matched_pattern,
        confidence
        )
        VALUES(?,?,?,?,?,?,?)
        """,data)
        self.conn.commit()


    ###############################################################


    def update_risk(self,component,score):
        self.cursor.execute("""
        INSERT INTO risk_scores(component,score)
        VALUES(?,?)
        ON CONFLICT(component)
        DO UPDATE SET score=excluded.score
        """,(component,score))
        self.conn.commit()


    ###############################################################


    def add_live_pattern(self, pattern_name, risk_score):
        self.cursor.execute("SELECT occurrences FROM patterns WHERE pattern_name = ?", (pattern_name,))
        row = self.cursor.fetchone()
        
        if row:
            new_occurrences = row[0] + 1
            self.cursor.execute("""
                UPDATE patterns 
                SET occurrences = ?, risk_score = ? 
                WHERE pattern_name = ?
            """, (new_occurrences, risk_score, pattern_name))
        else:
            self.cursor.execute("""
                INSERT INTO patterns (pattern_name, occurrences, risk_score) 
                VALUES (?, 1, ?)
            """, (pattern_name, risk_score))
            
        self.conn.commit()


    ###############################################################


    def get_all_cves(self):
        self.cursor.execute("SELECT * FROM cves")
        return self.cursor.fetchall()


    ###############################################################


    def get_patterns(self):
        self.cursor.execute("SELECT * FROM patterns")
        return self.cursor.fetchall()


    ###############################################################


    def get_risk_scores(self):
        self.cursor.execute("SELECT * FROM risk_scores")
        return self.cursor.fetchall()


    ###############################################################


    def close(self):
        self.conn.close()
