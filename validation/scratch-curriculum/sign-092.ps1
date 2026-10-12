# Sign the already-built 0.9.2 installer with the password from
# Documents\signing_password.txt. No repack (tauri signer sign).
# The full `tauri build` hung at the interactive password prompt, but it had
# already finished the NSIS bundle at 14:51:10, so we sign that artifact.
# NEVER prints the password or key material.
$ErrorActionPreference = 'Stop'
$root = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose'
$exe  = Join-Path $root 'desktop\tauri\target\release\bundle\nsis\BlackRose_0.9.2_x64-setup.exe'
$pwFile = 'C:\Users\pc\Documents\signing_password.txt'

if (-not (Test-Path $pwFile)) { Write-Output 'password file missing'; exit 1 }
if (-not (Test-Path $exe))   { Write-Output 'installer missing'; exit 1 }
$pw = ([IO.File]::ReadAllText($pwFile)).Trim()
if (-not $pw) { Write-Output 'password file empty'; exit 1 }
Write-Output ('password loaded (' + $pw.Length + ' chars)')

$env:TAURI_SIGNING_PRIVATE_KEY = [IO.File]::ReadAllText('C:\Users\pc\.tauri\blackrose.key')
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $pw
Set-Location $root
node node_modules\@tauri-apps\cli\tauri.js signer sign $exe
$code = $LASTEXITCODE
Write-Output ('signer exit: ' + $code)

$sig = "$exe.sig"
if ($code -ne 0 -or -not (Test-Path $sig)) { Write-Output 'SIGN FAILED'; exit 1 }
Write-Output ('signed OK -> ' + (Split-Path $sig -Leaf) + ' (' + (Get-Item $sig).Length + ' bytes)')
