from PIL import Image, ImageFilter
import io
import numpy as np

class VisaStampForensics:
    @staticmethod
    def analyze_stamp_authenticity(image_bytes: bytes) -> dict:
        """
        Detects digitally superimposed/forged visa stamps via:
        1. Ink Bleed & Saturation Variance: Genuine rubber/wet stamps exhibit non-uniform pressure gradients.
        2. Edge Gradient Sharpness: Digital cut-paste stamps exhibit unnaturally razor-sharp boundary transitions.
        """
        try:
            img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            arr = np.array(img, dtype=np.float32)

            # Analyze blue/red/violet stamp ink channels (common consular stamp hues)
            r, g, b = arr[:, :, 0], arr[:, :, 1], arr[:, :, 2]
            
            # Mask for stamp ink regions (predominantly purple/blue or red ink)
            stamp_mask = ((b > r * 1.15) & (b > 60)) | ((r > g * 1.3) & (r > 70))
            
            if np.sum(stamp_mask) < 200:
                return {
                    "stamp_detected": False,
                    "tampering_detected": False,
                    "ink_bleed_variance": 0.0,
                    "edge_artifact_score": 0.0,
                    "status": "NO_PROMINENT_STAMP_FOUND"
                }

            stamp_pixels = arr[stamp_mask]
            saturation_var = float(np.var(stamp_pixels))

            # Edge sharpness of the stamp mask
            stamp_mask_img = Image.fromarray((stamp_mask * 255).astype(np.uint8))
            edges = stamp_mask_img.filter(ImageFilter.FIND_EDGES)
            edge_arr = np.array(edges)
            edge_sharpness = float(np.mean(edge_arr[edge_arr > 0])) if np.any(edge_arr > 0) else 0.0

            # Digital cut-pastes have very LOW saturation variance (uniform color) + very HIGH edge sharpness
            is_digital_forgery = (saturation_var < 420.0 and edge_sharpness > 140.0)

            return {
                "stamp_detected": True,
                "tampering_detected": is_digital_forgery,
                "ink_bleed_variance": round(saturation_var, 2),
                "edge_artifact_score": round(edge_sharpness, 2),
                "status": "FORGED_DIGITAL_STAMP" if is_digital_forgery else "GENUINE_WET_INK_STAMP"
            }
        except Exception as e:
            return {"stamp_detected": False, "tampering_detected": False, "error": str(e)}
