import numpy as np
import hashlib

class BiometricsEngine:
    def __init__(self):
        # Simulated pre-populated watchlist vector index (1:N Faiss-equivalent in pure NumPy)
        # Format: (id_number, 128-d normalized embedding vector)
        np.random.seed(42)
        self.watchlist = [
            (f"WL-IND-202{i}", np.random.randn(128) / np.linalg.norm(np.random.randn(128)))
            for i in range(25)
        ]

    def _generate_deterministic_embedding(self, image_bytes: bytes) -> np.ndarray:
        """Derives a normalized 128-d facial embedding based on perceptual image hash."""
        h = hashlib.sha256(image_bytes).digest()
        # Seed pseudo-random generator with hash bytes to simulate consistent face vectors
        seed = int.from_bytes(h[:4], 'big')
        rng = np.random.RandomState(seed)
        vec = rng.randn(128)
        return vec / np.linalg.norm(vec)

    def verify_1_to_1(self, doc_face_bytes: bytes, live_face_bytes: bytes) -> float:
        """Calculates Cosine Similarity between document photo and live feed."""
        v1 = self._generate_deterministic_embedding(doc_face_bytes)
        v2 = self._generate_deterministic_embedding(live_face_bytes)
        similarity = float(np.dot(v1, v2))
        # Normalize from [-1, 1] to [0, 100] percentage score
        score = max(0.0, min(100.0, (similarity + 1.0) / 2.0 * 100.0))
        return round(score, 2)

    def check_1_to_n_mule(self, live_face_bytes: bytes, current_id: str, threshold: float = 0.75) -> dict:
        """1:N watchlist search for Identity Mule detection."""
        live_vec = self._generate_deterministic_embedding(live_face_bytes)
        matches = []

        for record_id, watch_vec in self.watchlist:
            sim = float(np.dot(live_vec, watch_vec))
            if sim >= threshold and record_id != current_id:
                matches.append({"suspect_id": record_id, "similarity": round(sim, 3)})

        is_mule = len(matches) > 0
        return {
            "identity_mule_flag": is_mule,
            "matched_records_count": len(matches),
            "flagged_matches": matches
        }
