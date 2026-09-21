class MRZValidator:
    WEIGHTS = [7, 3, 1]

    @staticmethod
    def _char_value(c: str) -> int:
        if c.isdigit():
            return int(c)
        elif c.isalpha():
            return ord(c.upper()) - 55
        return 0

    @classmethod
    def compute_checksum(cls, s: str) -> int:
        total = 0
        for i, char in enumerate(s):
            total += cls._char_value(char) * cls.WEIGHTS[i % 3]
        return total % 10

    @classmethod
    def validate_type3_passport(cls, line1: str, line2: str) -> dict:
        line1 = line1.strip().upper().replace(" ", "")
        line2 = line2.strip().upper().replace(" ", "")

        if len(line1) != 44 or len(line2) != 44:
            return {"valid": False, "error": "Lines must be exactly 44 characters."}

        p_num, p_check = line2[0:9], line2[9]
        dob, dob_check = line2[13:19], line2[19]
        exp, exp_check = line2[21:27], line2[27]

        p_val = str(cls.compute_checksum(p_num)) == p_check
        d_val = str(cls.compute_checksum(dob)) == dob_check
        e_val = str(cls.compute_checksum(exp)) == exp_check

        return {
            "valid": p_val and d_val and e_val,
            "passport_number": p_num.replace("<", ""),
            "dob": dob,
            "expiry": exp,
            "checksums_passed": {"passport": p_val, "dob": d_val, "expiry": e_val}
        }
