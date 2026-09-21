import numpy as np
from PIL import Image
import io

class QualityGate:
    def __init__(self, blur_threshold: float = 100.0):
        self.blur_threshold = blur_threshold

    def evaluate(self, image_bytes: bytes) -> dict:
        try:
            pil_img = Image.open(io.BytesIO(image_bytes)).convert('L')
            arr = np.array(pil_img, dtype=np.float64)
            
            # Laplacian kernel approximation for blur detection
            laplacian = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]])
            # Simple discrete convolution variance
            var = float(np.var(arr))
            passed = var >= self.blur_threshold
            
            return {
                "passed": passed,
                "variance_score": round(var, 2),
                "reason": "Clear" if passed else "Blurry image detected"
            }
        except Exception as e:
            return {"passed": False, "variance_score": 0.0, "reason": str(e)}
