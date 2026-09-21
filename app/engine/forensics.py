from PIL import Image, ImageChops, ImageEnhance
import io
import base64
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

            # Compute difference between original and resaved JPEG
            diff = ImageChops.difference(original, resaved)
            
            # Enhance brightness to make splicing artifacts visible to officers
            enhancer = ImageEnhance.Brightness(diff)
            enhanced_diff = enhancer.enhance(10.0)

            diff_arr = np.array(diff, dtype=np.float32)
            anomaly_score = float(np.mean(diff_arr))

            # Detect high-variance spliced patches for bounding box localization
            gray_diff = np.mean(diff_arr, axis=2)
            high_diff_mask = gray_diff > (np.mean(gray_diff) + 2.5 * np.std(gray_diff))
            
            bounding_boxes = []
            if np.any(high_diff_mask):
                y_indices, x_indices = np.where(high_diff_mask)
                h, w = gray_diff.shape
                # Normalize coordinates to percentages for frontend canvas rendering
                ymin = max(0, int(np.min(y_indices) / h * 100))
                ymax = min(100, int(np.max(y_indices) / h * 100))
                xmin = max(0, int(np.min(x_indices) / w * 100))
                xmax = min(100, int(np.max(x_indices) / w * 100))
                
                # Only add bounding box if it spans a noticeable document area
                if (ymax - ymin) > 5 and (xmax - xmin) > 5:
                    bounding_boxes.append({
                        "label": "Potential Splicing / Digital Artifact",
                        "box": [ymin, xmin, ymax, xmax]
                    })

            # Export ELA Heatmap as Base64 Data URI
            heatmap_io = io.BytesIO()
            enhanced_diff.save(heatmap_io, format="JPEG")
            heatmap_b64 = "data:image/jpeg;base64," + base64.b64encode(heatmap_io.getvalue()).decode("utf-8")

            tampered = anomaly_score > 10.5 or len(bounding_boxes) > 0
            return {
                "tampering_detected": tampered,
                "ela_anomaly_score": round(anomaly_score, 2),
                "risk_flag": "HIGH" if tampered else "LOW",
                "bounding_boxes": bounding_boxes,
                "ela_heatmap_b64": heatmap_b64
            }
        except Exception as e:
            return {"tampering_detected": False, "ela_anomaly_score": 0.0, "bounding_boxes": [], "error": str(e)}
