import hashlib
import hmac
import time
import uuid
from app.core.config import SECRET_SALT

class CryptoAuditLogger:
    @staticmethod
    def generate_audit_record(session_id: str, risk_score: float, triage_status: str, doc_bytes: bytes) -> dict:
        doc_hash = hashlib.sha256(doc_bytes).hexdigest()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
        payload = f"{session_id}|{timestamp}|{risk_score}|{triage_status}|{doc_hash}"
        signature = hmac.new(SECRET_SALT.encode(), payload.encode(), hashlib.sha256).hexdigest()
        
        return {
            "session_id": session_id,
            "timestamp": timestamp,
            "risk_score": risk_score,
            "triage_status": triage_status,
            "doc_sha256": doc_hash,
            "audit_signature": signature
        }
