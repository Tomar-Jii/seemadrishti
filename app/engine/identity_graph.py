import numpy as np

class IdentityGraphEngine:
    def __init__(self):
        # Synthetic Mule Syndicate Database linking suspect face nodes to fraudulent documents
        self.mock_network = {
            "MULE_NODE_1": {
                "primary_face_id": "FACE_VECTOR_88A",
                "linked_identities": [
                    {"name": "ARYAN TOMAR", "doc_no": "P8921443", "country": "IND", "status": "FLAGGED_FORGED_DOB"},
                    {"name": "ROHIT VERMA", "doc_no": "Z8834112", "country": "NPL", "status": "SUSPECT_MULE_PERMIT"},
                    {"name": "ANIL SHARMA", "doc_no": "V4490128", "country": "BTN", "status": "BLACK_MARKET_VISA"}
                ],
                "network_risk": "HIGH_CRITICAL"
            }
        }

    def evaluate_identity_network(self, doc_no: str, is_mule_trigger: bool) -> dict:
        if is_mule_trigger or doc_no in ["P8921443", "Z8834112"]:
            data = self.mock_network["MULE_NODE_1"]
            return {
                "graph_detected": True,
                "central_identity": "CROSS_BORDER_IDENTITY_SYNDICATE_#09",
                "risk_multiplier": 1.45,
                "nodes": [
                    {"id": "NODE_FACE", "label": "MATCHED_BIOMETRIC_PROFILE", "type": "BIOMETRIC_ROOT"},
                    {"id": "DOC_1", "label": "P8921443 (ARYAN TOMAR)", "type": "DOCUMENT_NODE", "flag": "FORGED"},
                    {"id": "DOC_2", "label": "Z8834112 (ROHIT VERMA)", "type": "DOCUMENT_NODE", "flag": "SUSPECT"},
                    {"id": "DOC_3", "label": "V4490128 (ANIL SHARMA)", "type": "DOCUMENT_NODE", "flag": "EXPIRED"}
                ],
                "edges": [
                    {"from": "NODE_FACE", "to": "DOC_1", "confidence": "98.4%"},
                    {"from": "NODE_FACE", "to": "DOC_2", "confidence": "95.1%"},
                    {"from": "NODE_FACE", "to": "DOC_3", "confidence": "91.8%"}
                ]
            }
        
        return {
            "graph_detected": False,
            "central_identity": "UNIQUE_INDIVIDUAL",
            "risk_multiplier": 1.0,
            "nodes": [
                {"id": "NODE_FACE", "label": "VERIFIED_BIOMETRIC", "type": "BIOMETRIC_ROOT"},
                {"id": "DOC_1", "label": doc_no or "GENUINE_CREDENTIAL", "type": "DOCUMENT_NODE", "flag": "CLEAN"}
            ],
            "edges": [{"from": "NODE_FACE", "to": "DOC_1", "confidence": "99.1%"}]
        }
