class OCRExtractorEngine:
    @staticmethod
    def extract_fields(mrz_data: dict) -> dict:
        """
        Maps extracted passport/ID fields with normalized UI canvas coordinates (percentages)
        for futuristic animated bounding box rendering on document viewport.
        """
        doc_num = mrz_data.get("passport_number", "Z1234567")
        dob = mrz_data.get("dob", "080405")
        exp = mrz_data.get("expiry", "280921")
        name = mrz_data.get("full_name", "ARYAN TOMAR")
        
        return {
            "fields": {
                "name": {"value": name, "confidence": 0.98, "box": [32, 28, 41, 75]},
                "dob": {"value": dob, "confidence": 0.96, "box": [43, 28, 51, 55]},
                "doc_no": {"value": doc_num, "confidence": 0.99, "box": [53, 28, 61, 58]},
                "expiry": {"value": exp, "confidence": 0.97, "box": [63, 28, 71, 58]},
                "mrz": {"value": "ICAO 9303 TD3", "confidence": 1.0, "box": [75, 5, 95, 95]}
            }
        }
