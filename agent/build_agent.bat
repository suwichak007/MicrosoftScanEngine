@echo off
cd /d "%~dp0"
echo ===== ติดตั้ง dependencies =====
pip install pyinstaller requests pandas openpyxl pywin32

echo ===== Build exe =====
pyinstaller agent.spec --clean --noconfirm

echo.
echo ===== เสร็จแล้ว =====
echo ไฟล์อยู่ที่: dist\MicrosoftScanAgent.exe
echo.
echo copy ไปวางบนเครื่องเป้าหมายพร้อมกับ:
echo   agent_config.json
echo   data\
pause