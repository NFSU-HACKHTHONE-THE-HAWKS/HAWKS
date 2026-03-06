import time

class NTFSAnalyzer:
    def __init__(self):
        # 1 second se zyada ka gap matlab abnormal
        self.THRESHOLD = 1.0 

    def analyze(self, si_time, fn_time, usn_time):
        """
        si_time: File MFT Standard Info (Easily forged)
        fn_time: File MFT Filename Info (Harder to forge)
        usn_time: USN Journal Entry (Actual event time)
        """
        # Logic 1: Timestomping Check ($SI vs $FN)
        mft_diff = abs(si_time - fn_time)
        
        # Logic 2: Journal Inconsistency ($SI vs USN Journal)
        # Agar Journal keh raha hai "Abhi change hua" par SI keh raha hai "2 saal pehle"
        journal_diff = abs(si_time - usn_time)

        if journal_diff > 3600: # 1 ghante se zyada ka gap
            return {
                "is_tampered": True,
                "score": 100,
                "msg": f"CRITICAL: Timestomping Detected! $SI and USN Journal mismatch by {round(journal_diff/60, 2)} minutes."
            }
        elif mft_diff > self.THRESHOLD:
            return {
                "is_tampered": True,
                "score": 85,
                "msg": "SUSPICIOUS: MFT Metadata ($SI vs $FN) Inconsistency."
            }
        
        return {"is_tampered": False, "score": 0, "msg": "Stable"}
    