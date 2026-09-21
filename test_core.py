from app.engine.mrz import MRZValidator

l1 = "P<INDKACHER<<ARYAN<<<<<<<<<<<<<<<<<<<<<<<<<<"
l2 = "Z1234567<8IND0804051M2809214<<<<<<<<<<<<<<0"

res = MRZValidator.validate_type3_passport(l1, l2)
print("=== MRZ VALIDATION TEST ===")
print("Passed:", res["valid"])
print("Details:", res)
