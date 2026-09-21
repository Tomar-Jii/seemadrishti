from PIL import Image, ImageChops, ImageEnhance
import io
import base64
import numpy as np
import cv2

class AdvancedForensicsEngine:
    @staticmethod
    def analyze_document_forensics(image_bytes: bytes) -> dict:
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img_cv = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img_cv is None:
            return {"error": "Invalid image"}

        h, w, _ = img_cv.shape

        # 1. Error Level Analysis (ELA)
        original = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        buffer = io.BytesIO()
        original.save(buffer, 'JPEG', quality=93)
        buffer.seek(0)
        resaved = Image.open(buffer)
        diff = ImageChops.difference(original, resaved)
        enhancer = ImageEnhance.Brightness(diff)
        enhanced_diff = enhancer.enhance(12.0)
        diff_arr = np.array(diff, dtype=np.float32)
        ela_score = float(np.mean(diff_arr))

        heatmap_io = io.BytesIO()
        enhanced_diff.save(heatmap_io, format="JPEG")
        ela_b64 = "data:image/jpeg;base64," + base64.b64encode(heatmap_io.getvalue()).decode("utf-8")

        # 2. Copy-Move / Clone Stamp Detection (SIFT / ORB Keypoint Clustering)
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        orb = cv2.ORB_create(nfeatures=600)
        kp, des = orb.detectAndCompute(gray, None)
        
        copy_move_detected = False
        clone_vectors = []
        if des is not None and len(des) > 15:
            bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
            matches = bf.knnMatch(des, des, k=2)
            
            # Lowe's ratio test to find duplicated visual patches
            for m, n in matches:
                if m.distance < 0.65 * n.distance and m.queryIdx != m.trainIdx:
                    pt1 = kp[m.queryIdx].pt
                    pt2 = kp[m.trainIdx].pt
                    dist = np.sqrt((pt1[0] - pt2[0])**2 + (pt1[1] - pt2[1])**2)
                    # Ignore neighbor points, catch long-range cloned pixels (stamps/faces)
                    if dist > 35:
                        copy_move_detected = True
                        clone_vectors.append({
                            "from": [round(pt1[0] / w * 100, 1), round(pt1[1] / h * 100, 1)],
                            "to": [round(pt2[0] / w * 100, 1), round(pt2[1] / h * 100, 1)]
                        })

        # 3. Font Consistency & Text Stroke Analysis (Laplacian Baseline Variance)
        # Spliced text often has abrupt gradient jumps in character stroke widths
        grad_x = cv2.Sobel(gray, cv2.CV_16S, 1, 0)
        grad_y = cv2.Sobel(gray, cv2.CV_16S, 0, 1)
        font_gradient_var = float(np.var(np.abs(grad_x) + np.abs(grad_y)))
        font_anomaly = font_gradient_var > 38000.0 or font_gradient_var < 1500.0

        tampered = ela_score > 11.5 or copy_move_detected or font_anomaly

        return {
            "tampering_detected": tampered,
            "ela_score": round(ela_score, 2),
            "ela_heatmap_b64": ela_b64,
            "copy_move": {
                "detected": copy_move_detected,
                "vector_count": len(clone_vectors),
                "vectors": clone_vectors[:20]
            },
            "font_consistency": {
                "gradient_variance": round(font_gradient_var, 1),
                "anomaly_detected": font_anomaly
            }
        }
