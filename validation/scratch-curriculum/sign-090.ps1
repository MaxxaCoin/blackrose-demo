# Sign the 0.9.0 installer with the password from Documents\signing_password.txt.
# NEVER prints the password or key material.
$ErrorActionPreference = 'Stop'
$pwFile = 'C:\Users\pc\Documents\signing_password.txt'
if (-not (Test-Path $pwFile)) { Write-Output 'password file missing'; exit 1 }
$pw = ([IO.File]::ReadAllText($pwFile)).Trim()
if (-not $pw) { Write-Output 'password file empty'; exit 1 }
Write-Output ('password loaded (' + $pw.Length + ' chars)')
$env:TAURI_SIGNING_PRIVATE_KEY = [IO.File]::ReadAllText('C:\Users\pc\.tauri\blackrose.key')
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $pw
Set-Location 'C:\Users\pc\Desktop\BlackRose\cline\blackrose'
node node_modules\@tauri-apps\cli\tauri.js signer sign 'desktop\tauri\target\release\bundle\nsis\BlackRose_0.9.0_x64-setup.exe'
Write-Output ('signer exit: ' + $LASTEXITCODE)
