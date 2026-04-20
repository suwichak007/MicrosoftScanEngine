import winreg
import pandas as pd
import os

class SecurityScanner:
    def __init__(self):
        self.results = {}
        self.passed = 0
        self.total = 0
        # ระบุ Path ของไฟล์ที่คุณนำมาวาง (สมมติว่าชื่อ baseline.xlsx)
        self.baseline_path = os.path.join("data", "MS Security Baseline Windows Server 2025 v2602.xlsx")

    def check_registry(self, hkey_str, path, value_name, expected_value, description):
        self.total += 1
        # แปลงชื่อ HKLM จากไฟล์ให้เป็น Object ของ winreg
        hkey = winreg.HKEY_LOCAL_MACHINE if "HKLM" in hkey_str else winreg.HKEY_CURRENT_USER
        
        try:
            with winreg.OpenKey(hkey, path) as key:
                actual_value, _ = winreg.QueryValueEx(key, value_name)
                # ตรวจสอบค่า (ต้องระวังเรื่องประเภทข้อมูล int หรือ string)
                if str(actual_value) == str(expected_value):
                    self.results[description] = "Pass"
                    self.passed += 1
                else:
                    self.results[description] = f"Fail (Expected {expected_value}, got {actual_value})"
        except FileNotFoundError:
            self.results[description] = "Not Configured"
        except Exception as e:
            self.results[description] = f"Error: {str(e)}"

    def run_baseline_2602(self):
        if not os.path.exists(self.baseline_path):
            return 0, {"Error": "Baseline file not found at " + self.baseline_path}

        # อ่านไฟล์ Excel
        df = pd.read_excel(self.baseline_path)

        # สมมติว่าไฟล์ Excel ของคุณมีคอลัมน์ชื่อ: Policy, Registry_Path, Value_Name, Recommended_Value
        for index, row in df.iterrows():
            self.check_registry(
                "HKLM", # หรือดึงจาก row['HKEY']
                row['Registry_Path'],
                row['Value_Name'],
                row['Recommended_Value'],
                row['Policy']
            )

        score = int((self.passed / self.total) * 100) if self.total > 0 else 0
        return score, self.results