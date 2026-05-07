@echo off
set AGENT_DIR=C:\MicrosoftScanEngine
set EXE=%AGENT_DIR%\MicrosoftScanAgent.exe
set NSSM=%AGENT_DIR%\nssm.exe

echo ===== ติดตั้ง MicrosoftScanAgent service =====
%NSSM% install MicrosoftScanAgent "%EXE%"
%NSSM% set MicrosoftScanAgent AppDirectory   "%AGENT_DIR%"
%NSSM% set MicrosoftScanAgent AppStdout      "%AGENT_DIR%\agent.log"
%NSSM% set MicrosoftScanAgent AppStderr      "%AGENT_DIR%\agent_err.log"
%NSSM% set MicrosoftScanAgent AppRotateFiles 1
%NSSM% set MicrosoftScanAgent AppRotateBytes 10485760
%NSSM% set MicrosoftScanAgent Start          SERVICE_AUTO_START
%NSSM% start MicrosoftScanAgent

echo.
sc query MicrosoftScanAgent
pause