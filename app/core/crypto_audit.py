import hashlib
import hmac
import time
import sqlite3
import os
from app.core.config import SECRET_SALT

DB_PATH = os.path.join(os.path.dirname(__file__), "audit_ledger.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                session_id TEXT PRIMARY KEY,
                timestamp TEXT,
                risk_score REAL,
                triage_status TEXT,
                doc_sha256 TEXT,
                audit_signature TEXT
            )
        """)
init_db()

class CryptoAuditLogger:
    @staticmethod
    def generate_audit_record(session_id: str, risk_score: float, triage_status: str, doc_bytes: bytes) -> dict:
        doc_hash = hashlib.sha256(doc_bytes).hexdigest()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
        payload = f"{session_id}|{timestamp}|{risk_score}|{triage_status}|{doc_hash}"
        signature = hmac.new(SECRET_SALT.encode(), payload.encode(), hashlib.sha256).hexdigest()
        
        record = {
            "session_id": session_id,
            "timestamp": timestamp,
            "risk_score": risk_score,
            "triage_status": triage_status,
            "doc_sha256": doc_hash,
            "audit_signature": signature
        }

        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?)",
                    (session_id, timestamp, risk_score, triage_status, doc_hash, signature)
                )
        except Exception:
            pass

        return record

    @staticmethod
    def verify_record(session_id: str) -> dict:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT session_id, timestamp, risk_score, triage_status, doc_sha256, audit_signature FROM audit_logs WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            
        if not row:
            return {"verified": False, "reason": "Record not found in local cryptographic ledger"}

        s_id, ts, score, status, d_hash, sig = row
        payload = f"{s_id}|{ts}|{score}|{status}|{d_hash}"
        expected_sig = hmac.new(SECRET_SALT.encode(), payload.encode(), hashlib.sha256).hexdigest()

        is_intact = hmac.compare_digest(sig, expected_sig)
        return {
            "verified": is_intact,
            "session_id": s_id,
            "timestamp": ts,
            "triage_status": status,
            "doc_sha256": d_hash,
            "tamper_proof_status": "INTACT & VALID" if is_intact else "CORRUPTED / TAMPERED"
        }
