import hashlib
from typing import Optional

class CrossZoneAndWatchlistEngine:
    def __init__(self):
        # Simulated MHA / Interpol SLTD (Stolen and Lost Travel Documents) Edge Watchlist
        # Format: Document Number -> Watchlist Alert Details
        self.blacklist = {
            "Z9912044": {"alert_type": "INTERPOL_RED_NOTICE", "threat_level": "CRITICAL", "details": "Wanted for Transnational Financial Fraud & Forgery"},
            "P8921443": {"alert_type": "MHA_STOLEN_PASSPORT", "threat_level": "HIGH", "details": "Reported Lost/Stolen at Siliguri Sector (2025)"},
            "IND-ALERT-01": {"alert_type": "SUSPECTED_CROSS_BORDER_TRAFFICKER", "threat_level": "CRITICAL", "details": "Lookout Circular (LOC) Active"}
        }

    def verify_viz_vs_mrz(self, visual_name: Optional[str], visual_dob: Optional[str], mrz_name: Optional[str], mrz_dob: Optional[str]) -> dict:
        """
        Cross-checks visual printed zone data with machine readable zone (MRZ).
        Flags discrepancies caused by physical document scraping or partial forgeries.
        """
        discrepancies = []
        
        if visual_name and mrz_name:
            v_n = "".join(filter(str.isalnum, visual_name.upper()))
            m_n = "".join(filter(str.isalnum, mrz_name.upper()))
            if v_n != m_n and not (v_n in m_n or m_n in v_n):
                discrepancies.append(f"Name Divergence: Visual='{visual_name}' vs MRZ='{mrz_name}'")

        if visual_dob and mrz_dob:
            v_d = "".join(filter(str.isdigit, visual_dob))
            m_d = "".join(filter(str.isdigit, mrz_dob))
            # Compare YYMMDD or trailing components
            if len(v_d) >= 6 and len(m_d) >= 6 and v_d[-6:] != m_d[-6:]:
                discrepancies.append(f"DOB Mismatch: Visual='{visual_dob}' vs MRZ='{mrz_dob}'")

        has_conflict = len(discrepancies) > 0
        return {
            "cross_check_passed": not has_conflict,
            "discrepancies_count": len(discrepancies),
            "discrepancies": discrepancies,
            "flag": "PHYSICAL_ZONE_SCRAPED" if has_conflict else "SYNCHRONIZED"
        }

    def check_watchlist(self, doc_number: str) -> dict:
        """Sub-millisecond Edge Watchlist / Interpol SLTD check."""
        clean_id = doc_number.strip().upper().replace("<", "")
        if clean_id in self.blacklist:
            info = self.blacklist[clean_id]
            return {
                "watchlist_hit": True,
                "threat_level": info["threat_level"],
                "alert_type": info["alert_type"],
                "details": info["details"]
            }
        return {"watchlist_hit": False, "threat_level": "NONE", "alert_type": "CLEAN"}
