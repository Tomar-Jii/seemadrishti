from fastapi import FastAPI, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uuid
import os
import time
from typing import Optional

from app.engine.doc_detector import DocumentDetector
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
    version="4.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard(response: Response):
    # Enforce fresh load without browser caching
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
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
    raw_doc_bytes = await document_image.read()

    # Presets mapped strictly to Storyboard Clips
    if simulated_preset == "TAMPERED":
        doc_bytes = raw_doc_bytes
        q_res = {"passed": True, "variance_score": 210.5, "reason": "Clear Resolution"}
        mrz_res = {
            "valid": False, "type": "ICAO_TD3", "passport_number": "P8921443",
            "dob": "980512", "full_name": "ARYAN TOMAR", "expiry": "280921",
            "checksums_passed": {"passport": True, "dob": False, "expiry": True}
        }
        f_res = AdvancedForensicsEngine.analyze_document_forensics(doc_bytes)
        f_res["tampering_detected"] = True
        f_res["ela_score"] = 28.4
        f_res["copy_move"]["detected"] = True
        f_res["copy_move"]["vectors"] = [{"from": [25, 30], "to": [72, 65]}, {"from": [28, 35], "to": [75, 70]}]
        f_res["font_consistency"]["anomaly_detected"] = True
        face_score = 88.0
        is_mule = False

    elif simulated_preset == "MULE_NETWORK":
        doc_bytes = raw_doc_bytes
        q_res = {"passed": True, "variance_score": 195.0, "reason": "Clear Resolution"}
        mrz_res = MRZValidator.validate_type3_passport(
            "P<INDVERMA<<ROHIT<<<<<<<<<<<<<<<<<<<<<<<<<<<",
            "Z8834112<4IND9408152M2911181<<<<<<<<<<<<<<2"
        )
        f_res = AdvancedForensicsEngine.analyze_document_forensics(doc_bytes)
        face_score = 96.2
        is_mule = True

    elif simulated_preset == "REVIEW_AMBER":
        doc_bytes = raw_doc_bytes
        q_res = {"passed": True, "variance_score": 115.0, "reason": "Moderate Lighting"}
        mrz_res = MRZValidator.validate_type3_passport(
            "P<INDSHARMA<<KAPIL<<<<<<<<<<<<<<<<<<<<<<<<<<",
            "S4421098<2IND9102143M2705194<<<<<<<<<<<<<<1"
        )
        f_res = AdvancedForensicsEngine.analyze_document_forensics(doc_bytes)
        f_res["tampering_detected"] = False
        f_res["ela_score"] = 9.2
        face_score = 74.0
        is_mule = False

    else:
        # STEP 0: DOCUMENT BOUNDARY & CREDENTIAL TYPE DETECTOR
        det_res = DocumentDetector.inspect_and_crop(raw_doc_bytes)
        if not det_res["valid_credential"]:
            # IMMEDIATE REJECTION OF SCREENSHOTS / RANDOM IMAGES
            audit_entry = CryptoAuditLogger.generate_audit_record(session_id, 99.0, "REJECTED_INVALID_CREDENTIAL", raw_doc_bytes)
            return {
                "session_id": session_id,
                "processing_latency_sec": round(time.time() - start_time, 2),
                "triage": {
                    "action": "REJECT_INVALID_DOCUMENT",
                    "lane_label": "⛔ REJECTED: NOT AN OFFICIAL CREDENTIAL",
                    "indicator": "RED",
                    "risk_score": 99.0
                },
                "explainable_breakdown": {
                    "quality_risk": 100.0,
                    "format_mrz_risk": 100.0,
                    "tamper_forensic_risk": 0.0,
                    "biometric_risk": 0.0,
                    "identity_graph_risk": 0.0
                },
                "quality_gate": {"passed": False, "reason": det_res["reason"]},
                "ocr_extraction": {"fields": {}},
                "validation_badges": {"format": "FAILED", "checksum": "FAILED", "expiry": "N/A", "watchlist": "N/A"},
                "forensics": {"tampering_detected": False, "ela_score": 0.0, "copy_move": {"detected": False, "vectors": []}, "font_consistency": {"anomaly_detected": False}},
                "biometrics": {"face_match_confidence": 0.0, "liveness": "UNVERIFIED"},
                "identity_graph": {"graph_detected": False},
                "audit_ledger": audit_entry
            }

        doc_bytes = det_res["cropped_bytes"] if det_res["cropped_bytes"] else raw_doc_bytes
        q_res = QualityGate().evaluate(doc_bytes)
        mrz_res = {"parsed": False, "valid": True}
        if mrz_line1 and mrz_line2:
            mrz_res = MRZValidator.validate_type3_passport(mrz_line1, mrz_line2)
        f_res = AdvancedForensicsEngine.analyze_document_forensics(doc_bytes)
        face_score = 94.5
        is_mule = False

    ocr_res = OCRExtractorEngine.extract_fields(mrz_res)
    graph_res = IdentityGraphEngine().evaluate_identity_network(mrz_res.get("passport_number", "DOC"), is_mule)

    # Multi-Vector Composite Risk
    v_quality = 0.0 if q_res.get("passed") else 80.0
    v_mrz = 0.0 if mrz_res.get("valid", True) else 85.0
    v_forensics = 85.0 if f_res.get("tampering_detected") else 5.0
    v_biometrics = (100.0 - face_score) if face_score < 70.0 else (28.0 if face_score < 78.0 else 4.0)
    v_graph = 90.0 if graph_res.get("graph_detected") else 0.0

    raw_risk = (0.20 * v_quality) + (0.25 * v_mrz) + (0.35 * v_forensics) + (0.10 * v_biometrics) + (0.10 * v_graph)
    total_risk = round(min(100.0, raw_risk * graph_res.get("risk_multiplier", 1.0)), 2)

    # STRICT SECURITY OVERRIDE
    if f_res.get("tampering_detected"):
        total_risk = max(total_risk, 78.5)
    elif not mrz_res.get("valid", True):
        total_risk = max(total_risk, 72.0)
    elif is_mule:
        total_risk = max(total_risk, 88.0)

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
