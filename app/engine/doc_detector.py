import cv2
import numpy as np

class DocumentDetector:
    @staticmethod
    def inspect_and_crop(image_bytes: bytes) -> dict:
        """
        1. Rejects vertical phone screenshots (aspect ratio < 0.85).
        2. Detects 4-corner document polygon and extracts clean top-down rectangular crop.
        3. Verifies official credential aspect ratios (ID-1 / Passport TD3: 1.25 to 1.70).
        """
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is None:
            return {"valid_credential": False, "reason": "Corrupt or unreadable image stream.", "cropped_bytes": None}

        h, w, _ = img.shape
        raw_aspect = w / float(h)

        # REJECT IMMEDIATE: Vertical phone screenshots (like Google Forms/Chat screenshots)
        if raw_aspect < 0.85 or raw_aspect > 2.4:
            return {
                "valid_credential": False,
                "reason": f"Non-standard aspect ratio ({round(raw_aspect, 2)}). Expected horizontal Passport or National ID card, not a mobile screen capture.",
                "doc_type": "INVALID_SCREENSHOT",
                "cropped_bytes": None
            }

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edged = cv2.Canny(blurred, 50, 150)

        contours, _ = cv2.findContours(edged, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        contours = sorted(contours, key=cv2.contourArea, reverse=True)[:5]

        doc_contour = None
        img_area = w * h

        for c in contours:
            peri = cv2.arcLength(c, True)
            approx = cv2.approxPolyDP(c, 0.02 * peri, True)
            area = cv2.contourArea(approx)

            # Document must cover at least 20% of the camera viewfinder
            if len(approx) == 4 and area > (0.20 * img_area):
                doc_contour = approx
                break

        # If a prominent 4-corner document contour is found, warp perspective
        if doc_contour is not None:
            pts = doc_contour.reshape(4, 2).astype("float32")
            # Order coordinates: top-left, top-right, bottom-right, bottom-left
            rect = np.zeros((4, 2), dtype="float32")
            s = pts.sum(axis=1)
            rect[0] = pts[np.argmin(s)]
            rect[2] = pts[np.argmax(s)]
            diff = np.diff(pts, axis=1)
            rect[1] = pts[np.argmin(diff)]
            rect[3] = pts[np.argmax(diff)]

            (tl, tr, br, bl) = rect
            widthA = np.sqrt(((br[0] - bl[0]) ** 2) + ((br[1] - bl[1]) ** 2))
            widthB = np.sqrt(((tr[0] - tl[0]) ** 2) + ((tr[1] - tl[1]) ** 2))
            maxWidth = max(int(widthA), int(widthB))

            heightA = np.sqrt(((tr[0] - br[0]) ** 2) + ((tr[1] - br[1]) ** 2))
            heightB = np.sqrt(((tl[0] - bl[0]) ** 2) + ((tl[1] - bl[1]) ** 2))
            maxHeight = max(int(heightA), int(heightB))

            if maxHeight > 0 and maxWidth > 0:
                dst = np.array([
                    [0, 0],
                    [maxWidth - 1, 0],
                    [maxWidth - 1, maxHeight - 1],
                    [0, maxHeight - 1]], dtype="float32")

                M = cv2.getPerspectiveTransform(rect, dst)
                warped = cv2.warpPerspective(img, M, (maxWidth, maxHeight))
                _, encoded_crop = cv2.imencode(".jpg", warped)
                
                cropped_aspect = maxWidth / float(maxHeight)
                if 1.15 <= cropped_aspect <= 1.85:
                    return {
                        "valid_credential": True,
                        "reason": "Official document geometry detected & auto-cropped.",
                        "doc_type": "ICAO_STANDARDIZED_CREDENTIAL",
                        "cropped_bytes": encoded_crop.tobytes()
                    }

        # If no background noise was found (image is already a direct scan/crop)
        if 1.20 <= raw_aspect <= 1.75:
            return {
                "valid_credential": True,
                "reason": "Direct standardized document scan validated.",
                "doc_type": "DIRECT_DOCUMENT_SCAN",
                "cropped_bytes": image_bytes
            }

        return {
            "valid_credential": False,
            "reason": "No standardized identity card or passport structure detected in image frame.",
            "doc_type": "UNKNOWN_OBJECT",
            "cropped_bytes": None
        }
