# Auto-publish v0.9.1 when the build finishes:
#   1. wait for BlackRose_0.9.1_x64-setup.exe in the nsis bundle dir
#   2. sign it with the updater key (password from Documents file — never printed)
#   3. write BOM-less latest.json (version 0.9.1, new signature)
#   4. gh release create v0.9.1 with exe + sig + manifest
# Run detached: powershell -ExecutionPolicy Bypass -File publish-091-watch.ps1
$ErrorActionPreference = 'Continue'
$nsis = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\target\release\bundle\nsis'
$exe = Join-Path $nsis 'BlackRose_0.9.1_x64-setup.exe'
$sig = "$exe.sig"

Write-Output ("watcher started " + (Get-Date -Format 'HH:mm:ss'))
$deadline = (Get-Date).AddMinutes(75)
while (-not (Test-Path $sig)) {
  if ((Get-Date) -gt $deadline) { Write-Output 'TIMEOUT waiting for build'; exit 1 }
  Start-Sleep -Seconds 30
}
Start-Sleep -Seconds 10
Write-Output ("installer ready " + (Get-Date -Format 'HH:mm:ss') + " size " + (Get-Item $exe).Length)

# --- sign ---
$pw = ([IO.File]::ReadAllText('C:\Users\pc\Documents\signing_password.txt')).Trim()
$env:TAURI_SIGNING_PRIVATE_KEY = [IO.File]::ReadAllText('C:\Users\pc\.tauri\blackrose.key')
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $pw
Set-Location 'C:\Users\pc\Desktop\BlackRose\cline\blackrose'
node node_modules\@tauri-apps\cli\tauri.js signer sign $exe 2>&1 | Select-Object -Last 2
if (-not (Test-Path $sig) -or (Get-Item $sig).LastWriteTime -lt (Get-Date).AddMinutes(-5)) {
  Write-Output 'SIGN FAILED (no fresh .sig)'; exit 1
}
Write-Output 'signed OK'

# --- latest.json (BOM-less) ---
$signature = ([IO.File]::ReadAllText($sig)).Trim()
$manifest = @{
  version  = '0.9.1'
  notes    = 'Mic button (offline voice input) in the composer, yt-dlp hardening, knowledge tools fix'
  pub_date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd\THH:mm:ss.fff\Z')
  platforms = @{
    'windows-x86_64' = @{
      signature = $signature
      url = 'https://github.com/MaxxaCoin/BlackRose/releases/download/v0.9.1/BlackRose_0.9.1_x64-setup.exe'
    }
  }
}
$json = $manifest | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $nsis 'latest.json'), $json)
$bytes = [IO.File]::ReadAllBytes((Join-Path $nsis 'latest.json'))
if ($bytes[0] -eq 0xEF) { Write-Output 'BOM DETECTED — aborting'; exit 1 }
Write-Output 'latest.json written (BOM-less)'

# --- release ---
gh release create v0.9.1 --repo MaxxaCoin/BlackRose --title 'BlackRose 0.9.1' --notes 'Push-to-talk mic button (offline local voice input) in the composer; hardened video downloads; knowledge-base robustness fix. Installed 0.9.0 apps will offer this update automatically.' "$exe" "$sig" (Join-Path $nsis 'latest.json') 2>&1 | Select-Object -Last 2
Write-Output ("release exit: " + $LASTEXITCODE)
Write-Output 'PUBLISH DONE'
