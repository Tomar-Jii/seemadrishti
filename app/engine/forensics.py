from PIL import Image, ImageChops
import io
import numpy as np

class ForensicsEngine:
    @staticmethod
    def compute_ela_score(image_bytes: bytes, quality: int = 95) -> dict:
        try:
            original = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            buffer = io.BytesIO()
            original.save(buffer, 'JPEG', quality=quality)
            buffer.seek(0)
            resaved = Image.open(buffer)

            diff = ImageChops.difference(original, resaved)
            diff_arr = np.array(diff, dtype=np.float32)
            anomaly_score = float(np.mean(diff_arr))

            # Scaled score: higher mean difference -> higher probability of spliced artifact
            tampered = anomaly_score > 12.0
            return {
                "tampering_detected": tampered,
                "ela_anomaly_score": round(anomaly_score, 2),
                "risk_flag": "HIGH" if tampered else "LOW"
            }
        except Exception as e:
            return {"tampering_detected": False, "ela_anomaly_score": 0.0, "error": str(e)}
