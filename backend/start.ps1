Set-Service WinRM -StartupType Automatic
Start-Service WinRM

while ((Get-Service WinRM).Status -ne 'Running') {
    Start-Sleep -Seconds 1
}

$envPath = Join-Path $PSScriptRoot "..\.env"
if (Test-Path $envPath) {
    foreach ($envLine in Get-Content $envPath) {
        $line = $envLine.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) {
            continue
        }
        $parts = $line.Split("=", 2)
        [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
    }
}

$logPath = Join-Path $PSScriptRoot "start_env.log"
$tokenLength = ($env:AGENT_INSTALL_TOKEN | ForEach-Object { if ($_) { $_.Length } else { 0 } })
$pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
"$(Get-Date -Format o) envPath=$envPath envExists=$(Test-Path $envPath) tokenLength=$tokenLength python=$pythonPath" | Out-File -FilePath $logPath -Append -Encoding utf8

Write-Host "Configuring WinRM Client..."
winrm set winrm/config/client '@{AllowUnencrypted="true"}'
winrm set winrm/config/client/auth '@{Basic="true"}'
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force

Write-Host "Starting Uvicorn..."
python -m uvicorn main:app --app-dir $PSScriptRoot --host 0.0.0.0 --port 8000 --no-access-log
