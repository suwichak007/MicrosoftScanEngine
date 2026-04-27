Set-Service WinRM -StartupType Automatic
Start-Service WinRM

while ((Get-Service WinRM).Status -ne 'Running') {
    Start-Sleep -Seconds 1
}

Write-Host "Configuring WinRM Client..."
winrm set winrm/config/client '@{AllowUnencrypted="true"}'
winrm set winrm/config/client/auth '@{Basic="true"}'
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force

Write-Host "Starting Uvicorn..."
python -m uvicorn main:app --host 0.0.0.0 --port 8000