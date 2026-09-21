from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uuid
import os
from typing import Optional

from app.engine.quality import QualityGate
from app.engine.forensics import ForensicsEngine
from app.engine.mrz import MRZValidator
from app.engine.biometrics import BiometricsEngine
from app.core.crypto_audit import CryptoAuditLogger

app = FastAPI(
    title="SeemaDrishti - Border Security Core API",
    description="Automated AI fake document, forensic tampering and biometric verification engine for SSB border checkposts.",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

quality_gate = QualityGate()
forensics = ForensicsEngine()
biometrics = BiometricsEngine()

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/v1/health")
def health_check():
    return {
        "status": "OPERATIONAL",
        "system": "SeemaDrishti Terminal Node",
        "compliance": "DPDP Act 2023 Compliant (Zero-PII Ledger)"
    }

@app.post("/api/v1/screen-traveler")
async def screen_traveler(
    document_image: UploadFile = File(...),
    live_face_image: Optional[UploadFile] = File(None),
    mrz_line1: Optional[str] = Form(None),
    mrz_line2: Optional[str] = Form(None)
):
    session_id = str(uuid.uuid4())
    doc_bytes = await document_image.read()

    # Stage 1: Quality Gate (< 100ms)
    q_res = quality_gate.evaluate(doc_bytes)
    if not q_res["passed"]:
        return {
            "session_id": session_id,
            "triage_summary": {"status": "RETAKE_DOCUMENT", "indicator": "AMBER", "overall_risk_score": 45.0},
            "quality_gate": q_res,
            "message": "Recapture required due to blur or severe lamination glare."
        }

    # Stage 2: MRZ Checksum Validation
    mrz_res = {"parsed": False, "valid": True}
    if mrz_line1 and mrz_line2:
        mrz_res = MRZValidator.validate_type3_passport(mrz_line1, mrz_line2)

    # Stage 3: Tampering Forensics (ELA + Heatmap generation)
    f_res = forensics.compute_ela_score(doc_bytes)

    # Stage 4: Biometric Matching & 1:N Mule Check
    face_score = 92.5
    mule_res = {"identity_mule_flag": False}
    if live_face_image:
        live_bytes = await live_face_image.read()
        face_score = biometrics.verify_1_to_1(doc_bytes, live_bytes)
        doc_num = mrz_res.get("passport_number", "DOC_UNKNOWN")
        mule_res = biometrics.check_1_to_n_mule(live_bytes, doc_num)

    # Stage 5: Weighted Risk Scoring
    forensic_risk = 70.0 if f_res.get("tampering_detected") else 10.0
    mrz_risk = 0.0 if mrz_res.get("valid", True) else 80.0
    bio_risk = (100.0 - face_score) if face_score < 70.0 else 5.0
    if mule_res.get("identity_mule_flag"):
        bio_risk += 50.0

    total_risk = round(0.4 * forensic_risk + 0.3 * mrz_risk + 0.3 * bio_risk, 2)

    if total_risk < 25.0:
        triage = "AUTO_CLEAR"
        color = "GREEN"
    elif total_risk <= 60.0:
        triage = "SECONDARY_INSPECTION"
        color = "AMBER"
    else:
        triage = "DETAIN_CRITICAL_ALERT"
        color = "RED"

    # Stage 6: DPDP Act 2023 Zero-PII Audit Ledger Entry
    audit_entry = CryptoAuditLogger.generate_audit_record(session_id, total_risk, triage, doc_bytes)

    return {
        "session_id": session_id,
        "triage_summary": {
            "status": triage,
            "indicator": color,
            "overall_risk_score": total_risk
        },
        "quality_gate": q_res,
        "mrz_validation": mrz_res,
        "forensics": f_res,
        "biometrics": {
            "face_match_score": face_score,
            "mule_detection": mule_res
        },
        "audit_ledger": audit_entry
    }
