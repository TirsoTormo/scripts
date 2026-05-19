"""
Argos - OS Fingerprinting Heuristics
====================================
Lightweight engine to identify Operating Systems based on network stack artifacts:
- TTL (Time To Live)
- TCP Window Size
- MSS (Maximum Segment Size)
"""


class OSFingerprinter:
    # Heuristics based on common TCP/IP stack defaults
    # TTL values:
    # 64  -> Linux / Unix / macOS / Android / iOS / IoT
    # 128 -> Windows (all versions)
    # 255 -> Network devices (Cisco, MikroTik, etc.) or Solaris

    @staticmethod
    def identify_os_from_ttl(ttl: int) -> str:
        """Heuristic OS identification based only on TTL."""
        if not ttl:
            return "Unknown"

        # Standard TTLs
        if ttl <= 64:
            return "Linux / Unix / Mobile"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Network Device / Solaris"
        return "Unknown"

    @staticmethod
    def identify_os_advanced(
        ttl: int, window_size: int | None = None, mss: int | None = None
    ) -> dict[str, any]:
        """Advanced heuristic combining multiple TCP/IP parameters."""
        score = {"Windows": 0, "Linux": 0, "Network": 0}

        # TTL heuristics
        if 60 <= ttl <= 64:
            score["Linux"] += 10
        elif 100 <= ttl <= 128:
            score["Windows"] += 10
        elif 250 <= ttl <= 255:
            score["Network"] += 10

        # Window size heuristics (rough)
        if window_size is not None:
            if window_size == 65535:  # Commonly Windows or Cisco
                score["Windows"] += 2
                score["Network"] += 1
            elif window_size in [5840, 14600, 29200]:  # Commonly Linux
                score["Linux"] += 5

        # Result calculation
        sorted_scores = sorted(score.items(), key=lambda x: x[1], reverse=True)
        best_match, points = sorted_scores[0]

        if points == 0:
            return {"os": "Unknown", "confidence": 0}

        return {
            "os": best_match,
            "confidence": min(points * 10, 100),  # Simple confidence mapping
            "scores": score,
        }
