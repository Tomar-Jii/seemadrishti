from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uuid
import os
from typing import Optional

from app.engine.quality import QualityGate
from app.engine.forensics import ForensicsEngine
from app.engine.mrz import MRZValidator
from app.engine.biometrics import BiometricsEngine
from app.engine.stamp_forensics import VisaStampForensics
from app.engine.viz_crosscheck import CrossZoneAndWatchlistEngine
from app.core.crypto_audit import CryptoAuditLogger

app = FastAPI(
    title="SeemaDrishti - Border Security Core API",
    description="Automated AI fake document, stamp forensics and biometric verification engine for SSB border checkposts.",
    version="2.4.0"
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
stamp_forensics = VisaStampForensics()
cross_engine = CrossZoneAndWatchlistEngine()

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/v1/health")
def health_check():
    pending_sync = CryptoAuditLogger.get_pending_sync_count()
    return {
        "status": "OPERATIONAL",
        "system": "SeemaDrishti Terminal Node #04",
        "pending_offline_sync": pending_sync,
        "compliance": "DPDP Act 2023 Compliant (Zero-PII Ledger)"
    }

@app.post("/api/v1/batch-sync")
def batch_sync():
    return CryptoAuditLogger.batch_sync_merkle()

@app.get("/api/v1/audit/verify/{session_id}")
def verify_audit_ledger(session_id: str):
    res = CryptoAuditLogger.verify_record(session_id)
    if not res.get("verified") and "not found" in res.get("reason", "").lower():
        raise HTTPException(status_code=404, detail="Audit record not found on terminal ledger.")
    return res

@app.post("/api/v1/screen-traveler")
async def screen_traveler(
    document_image: UploadFile = File(...),
    visa_image: Optional[UploadFile] = File(None),
    live_face_image: Optional[UploadFile] = File(None),
    mrz_line1: Optional[str] = Form(None),
    mrz_line2: Optional[str] = Form(None),
    visual_name: Optional[str] = Form(None),
    visual_dob: Optional[str] = Form(None),
    simulated_preset: Optional[str] = Form(None),
    offline_mode: Optional[bool] = Form(False)
):
    session_id = str(uuid.uuid4())
    doc_bytes = await document_image.read()

    # Preset Overrides for 100% Deterministic Demonstrations
    if simulated_preset == "TAMPERED":
        q_res = {"passed": True, "variance_score": 182.4, "reason": "Clear"}
        mrz_res = {
            "valid": False, "type": "ICAO_TD3_PASSPORT", "passport_number": "P8921443",
            "dob": "980512", "checksums_passed": {"passport": True, "dob": False, "expiry": True}
        }
        f_res = forensics.compute_ela_score(doc_bytes)
        f_res["tampering_detected"] = True
        f_res["ela_anomaly_score"] = 24.8
        f_res["bounding_boxes"] = [{"label": "Spliced Photo Boundary & Tampered DOB", "box": [22, 12, 68, 48]}]
        stamp_res = {"stamp_detected": False, "tampering_detected": False, "status": "N/A"}
        face_score = 88.0
        mule_res = {"identity_mule_flag": False}
        viz_res = {"cross_check_passed": False, "discrepancies": ["DOB Mismatch: Visual='12/05/1998' vs MRZ='05/04/2008'"]}
        watchlist_res = cross_engine.check_watchlist("P8921443")

    elif simulated_preset == "INTERPOL_HIT":
        q_res = {"passed": True, "variance_score": 190.0, "reason": "Clear"}
        mrz_res = MRZValidator.validate_type3_passport(
            "P<INDMALHOTRA<<VIKRAM<<<<<<<<<<<<<<<<<<<<<<<",
            "Z9912044<1IND8503104M2710192<<<<<<<<<<<<<<0"
        )
        f_res = forensics.compute_ela_score(doc_bytes)
        stamp_res = {"stamp_detected": False, "tampering_detected": False, "status": "N/A"}
        face_score = 91.0
        mule_res = {"identity_mule_flag": False}
        viz_res = {"cross_check_passed": True, "discrepancies": []}
        watchlist_res = cross_engine.check_watchlist("Z9912044")

    elif simulated_preset == "VISA_FORGERY":
        q_res = {"passed": True, "variance_score": 195.0, "reason": "Clear"}
        mrz_res = MRZValidator.validate_type3_passport(
            "P<INDKACHER<<ARYAN<<<<<<<<<<<<<<<<<<<<<<<<<<",
            "Z1234567<8IND0804051M2809214<<<<<<<<<<<<<<0"
        )
        f_res = forensics.compute_ela_score(doc_bytes)
        stamp_res = {
            "stamp_detected": True,
            "tampering_detected": True,
            "ink_bleed_variance": 198.4,
            "edge_artifact_score": 182.2,
            "status": "FORGED_DIGITAL_STAMP (UNNATURAL INK GRADIENT)"
        }
        face_score = 95.0
        mule_res = {"identity_mule_flag": False}
        viz_res = {"cross_check_passed": True, "discrepancies": []}
        watchlist_res = cross_engine.check_watchlist("Z1234567")

    elif simulated_preset == "MULE":
        q_res = {"passed": True, "variance_score": 164.0, "reason": "Clear"}
        mrz_res = MRZValidator.validate_type3_passport(
            "P<INDVERMA<<ROHIT<<<<<<<<<<<<<<<<<<<<<<<<<<<",
            "Z8834112<4IND9408152M2911181<<<<<<<<<<<<<<2"
        )
        f_res = forensics.compute_ela_score(doc_bytes)
        stamp_res = {"stamp_detected": False, "tampering_detected": False, "status": "N/A"}
        face_score = 94.2
        mule_res = {
            "identity_mule_flag": True, "matched_records_count": 2,
            "flagged_matches": [{"suspect_id": "WL-IND-2023-A09", "similarity": 0.912}]
        }
        viz_res = {"cross_check_passed": True, "discrepancies": []}
        watchlist_res = cross_engine.check_watchlist("Z8834112")

    else:
        # Standard Dynamic Execution Pipeline
        q_res = quality_gate.evaluate(doc_bytes)
        if not q_res["passed"]:
            return {
                "session_id": session_id,
                "triage_summary": {"status": "RETAKE_DOCUMENT", "indicator": "AMBER", "overall_risk_score": 45.0},
                "quality_gate": q_res,
                "message": "Immediate document recapture required due to blur or high glare."
            }

        mrz_res = {"parsed": False, "valid": True}
        if mrz_line1 and mrz_line2:
            mrz_res = MRZValidator.validate_type3_passport(mrz_line1, mrz_line2)

        f_res = forensics.compute_ela_score(doc_bytes)

        stamp_bytes = await visa_image.read() if visa_image else doc_bytes
        stamp_res = stamp_forensics.analyze_stamp_authenticity(stamp_bytes)

        # Cross-Zone Check (VIZ vs MRZ)
        mrz_name_extracted = mrz_res.get("full_name")
        mrz_dob_extracted = mrz_res.get("dob")
        viz_res = cross_engine.verify_viz_vs_mrz(visual_name, visual_dob, mrz_name_extracted, mrz_dob_extracted)

        # Watchlist / Interpol check
        doc_num = mrz_res.get("passport_number", "DOC_UNKNOWN")
        watchlist_res = cross_engine.check_watchlist(doc_num)

        face_score = 92.5
        mule_res = {"identity_mule_flag": False}
        if live_face_image:
            live_bytes = await live_face_image.read()
            face_score = biometrics.verify_1_to_1(doc_bytes, live_bytes)
            mule_res = biometrics.check_1_to_n_mule(live_bytes, doc_num)

    # Risk Scoring Formula
    forensic_risk = 75.0 if f_res.get("tampering_detected") else 8.0
    stamp_risk = 85.0 if stamp_res.get("tampering_detected") else 0.0
    mrz_risk = 0.0 if mrz_res.get("valid", True) else 85.0
    viz_risk = 0.0 if viz_res.get("cross_check_passed", True) else 90.0
    bio_risk = (100.0 - face_score) if face_score < 70.0 else 5.0
    if mule_res.get("identity_mule_flag"):
        bio_risk += 60.0

    total_risk = round(0.30 * forensic_risk + 0.15 * stamp_risk + 0.20 * mrz_risk + 0.15 * viz_risk + 0.20 * bio_risk, 2)

    if watchlist_res.get("watchlist_hit"):
        total_risk = 99.5
        triage = f"RED_ALERT_{watchlist_res['alert_type']}"
        color = "RED"
    elif total_risk < 25.0:
        triage = "AUTO_CLEAR"
        color = "GREEN"
    elif total_risk <= 60.0:
        triage = "SECONDARY_INSPECTION"
        color = "AMBER"
    else:
        triage = "DETAIN_CRITICAL_ALERT"
        color = "RED"

    # DPDP Act 2023 Ledger Proof
    audit_entry = CryptoAuditLogger.generate_audit_record(session_id, total_risk, triage, doc_bytes, offline=offline_mode)

    return {
        "session_id": session_id,
        "triage_summary": {
            "status": triage,
            "indicator": color,
            "overall_risk_score": total_risk
        },
        "quality_gate": q_res,
        "mrz_validation": mrz_res,
        "viz_crosscheck": viz_res,
        "watchlist": watchlist_res,
        "forensics": f_res,
        "stamp_forensics": stamp_res,
        "biometrics": {
            "face_match_score": face_score,
            "mule_detection": mule_res
        },
        "audit_ledger": audit_entry
    }
