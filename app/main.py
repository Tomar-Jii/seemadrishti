from fastapi import FastAPI, UploadFile, File
import uuid
from app.engine.quality import QualityGate
from app.engine.forensics import ForensicsEngine
from app.core.crypto_audit import CryptoAuditLogger

app = FastAPI(title="SeemaDrishti API", version="1.0.0")

quality_gate = QualityGate()
forensics = ForensicsEngine()

@app.get("/")
def health_check():
    return {"status": "ACTIVE", "system": "SeemaDrishti Border Screening Core"}

@app.post("/api/v1/screen-document")
async def screen_document(document: UploadFile = File(...)):
    session_id = str(uuid.uuid4())
    doc_bytes = await document.read()

    q_res = quality_gate.evaluate(doc_bytes)
    if not q_res["passed"]:
        return {"session_id": session_id, "triage": "RETAKE", "reason": q_res["reason"]}

    f_res = forensics.compute_ela_score(doc_bytes)
    risk_score = 75.0 if f_res["tampering_detected"] else 10.0
    triage = "HIGH" if risk_score > 50 else "LOW"

    audit_entry = CryptoAuditLogger.generate_audit_record(session_id, risk_score, triage, doc_bytes)

    return {
        "session_id": session_id,
        "quality_gate": q_res,
        "forensics": f_res,
        "risk_score": risk_score,
        "triage_status": triage,
        "audit_ledger": audit_entry
    }
