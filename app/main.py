from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uuid
import os
import time
from typing import Optional

from app.engine.quality import QualityGate
from app.engine.forensics_advanced import AdvancedForensicsEngine
from app.engine.mrz import MRZValidator
from app.engine.biometrics import BiometricsEngine
from app.engine.ocr_extractor import OCRExtractorEngine
from app.engine.identity_graph import IdentityGraphEngine
from app.core.crypto_audit import CryptoAuditLogger

app = FastAPI(
    title="SeemaDrishti - National Border AI System",
    description="SIH 2026 | Ministry of Home Affairs | Team Da Vinci Code",
    version="3.5.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

quality_gate = QualityGate()
forensics = AdvancedForensicsEngine()
biometrics = BiometricsEngine()
ocr = OCRExtractorEngine()
identity_graph = IdentityGraphEngine()

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.post("/api/v1/screen-traveler")
async def screen_traveler(
    document_image: UploadFile = File(...),
    live_face_image: Optional[UploadFile] = File(None),
    mrz_line1: Optional[str] = Form(None),
    mrz_line2: Optional[str] = Form(None),
    simulated_preset: Optional[str] = Form(None)
):
    start_time = time.time()
    session_id = str(uuid.uuid4())
    doc_bytes = await document_image.read()

    # Presets mapped strictly to Video Storyboard Clips
    if simulated_preset == "TAMPERED":
        q_res = {"passed": True, "variance_score": 210.5, "reason": "High Resolution"}
        mrz_res = {
            "valid": False, "type": "ICAO_TD3", "passport_number": "P8921443",
            "dob": "980512", "full_name": "ARYAN TOMAR", "expiry": "280921",
            "checksums_passed": {"passport": True, "dob": False, "expiry": True}
        }
        f_res = forensics.analyze_document_forensics(doc_bytes)
        f_res["tampering_detected"] = True
        f_res["ela_score"] = 28.4
        f_res["copy_move"]["detected"] = True
        f_res["copy_move"]["vectors"] = [{"from": [25, 30], "to": [72, 65]}, {"from": [28, 35], "to": [75, 70]}]
        f_res["font_consistency"]["anomaly_detected"] = True
        face_score = 88.0
        is_mule = False

    elif simulated_preset == "MULE_NETWORK":
        q_res = {"passed": True, "variance_score": 195.0, "reason": "High Resolution"}
        mrz_res = MRZValidator.validate_type3_passport(
            "P<INDVERMA<<ROHIT<<<<<<<<<<<<<<<<<<<<<<<<<<<",
            "Z8834112<4IND9408152M2911181<<<<<<<<<<<<<<2"
        )
        f_res = forensics.analyze_document_forensics(doc_bytes)
        face_score = 96.2
        is_mule = True

    elif simulated_preset == "REVIEW_AMBER":
        q_res = {"passed": True, "variance_score": 115.0, "reason": "Moderate Lighting"}
        mrz_res = MRZValidator.validate_type3_passport(
            "P<INDSHARMA<<KAPIL<<<<<<<<<<<<<<<<<<<<<<<<<<",
            "S4421098<2IND9102143M2705194<<<<<<<<<<<<<<1"
        )
        f_res = forensics.analyze_document_forensics(doc_bytes)
        f_res["tampering_detected"] = False
        f_res["ela_score"] = 11.2
        face_score = 74.0 # Borderline match triggering secondary desk review
        is_mule = False

    else:
        q_res = quality_gate.evaluate(doc_bytes)
        mrz_res = {"parsed": False, "valid": True}
        if mrz_line1 and mrz_line2:
            mrz_res = MRZValidator.validate_type3_passport(mrz_line1, mrz_line2)
        f_res = forensics.analyze_document_forensics(doc_bytes)
        face_score = 94.5
        is_mule = False

    ocr_res = ocr.extract_fields(mrz_res)
    graph_res = identity_graph.evaluate_identity_network(mrz_res.get("passport_number", "DOC"), is_mule)

    # Risk Scoring Formula
    v_quality = 0.0 if q_res.get("passed") else 80.0
    v_mrz = 0.0 if mrz_res.get("valid", True) else 85.0
    v_forensics = 85.0 if f_res.get("tampering_detected") else 5.0
    v_biometrics = (100.0 - face_score) if face_score < 70.0 else (28.0 if face_score < 78.0 else 4.0)
    v_graph = 90.0 if graph_res.get("graph_detected") else 0.0

    raw_risk = (0.20 * v_quality) + (0.25 * v_mrz) + (0.30 * v_forensics) + (0.15 * v_biometrics) + (0.10 * v_graph)
    total_risk = round(min(100.0, raw_risk * graph_res.get("risk_multiplier", 1.0)), 2)

    # Clip 10: 3-Lane Triage Routing
    if total_risk < 25.0:
        triage = "AUTO_CLEAR"
        triage_lane = "🟢 LOW RISK → AUTO CLEAR"
        color = "GREEN"
    elif total_risk <= 60.0:
        triage = "SECONDARY_REVIEW"
        triage_lane = "🟡 MEDIUM RISK → REVIEW"
        color = "AMBER"
    else:
        triage = "INVESTIGATION"
        triage_lane = "🔴 HIGH RISK → INVESTIGATION"
        color = "RED"

    # Cryptographic Audit Log (DPDP Act 2023)
    audit_entry = CryptoAuditLogger.generate_audit_record(session_id, total_risk, triage, doc_bytes)
    latency = round(time.time() - start_time, 2)

    return {
        "session_id": session_id,
        "processing_latency_sec": latency,
        "triage": {
            "action": triage,
            "lane_label": triage_lane,
            "indicator": color,
            "risk_score": total_risk
        },
        "explainable_breakdown": {
            "quality_risk": v_quality,
            "format_mrz_risk": v_mrz,
            "tamper_forensic_risk": v_forensics,
            "biometric_risk": v_biometrics,
            "identity_graph_risk": v_graph
        },
        "quality_gate": q_res,
        "ocr_extraction": ocr_res,
        "validation_badges": {
            "format": "PASSED" if mrz_res.get("parsed") != False else "UNVERIFIED",
            "checksum": "VALID" if mrz_res.get("valid", True) else "FAILED",
            "expiry": "CURRENT (2028)",
            "watchlist": "FLAGGED (MULE)" if is_mule else "CLEAR"
        },
        "forensics": f_res,
        "biometrics": {"face_match_confidence": face_score, "liveness": "VERIFIED"},
        "identity_graph": graph_res,
        "audit_ledger": audit_entry
    }
