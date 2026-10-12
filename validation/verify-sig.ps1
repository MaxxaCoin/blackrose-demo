$ErrorActionPreference = 'Stop'
$v     = 'C:\Users\pc\Desktop\BlackRose\validation'
$conf  = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\tauri.conf.json'
$nsis  = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\target\release\bundle\nsis'
$exe   = Join-Path $nsis 'BlackRose_0.9.16_x64-setup.exe'
$sig   = "$exe.sig"

# Derive the public key straight from tauri.conf.json - never hand-type it.
$upd = (Get-Content $conf -Raw | ConvertFrom-Json).plugins.updater
$key = $upd.pubkey; if (-not $key) { $key = $upd.pubKey }
$key = $key.Trim()
[IO.File]::WriteAllText((Join-Path $v 'pub.key'), $key, [Text.Encoding]::ASCII)
[IO.File]::WriteAllText((Join-Path $v 'sig.txt'), (Get-Content $sig -Raw).Trim(), [Text.Encoding]::ASCII)

Write-Host "exe      : $exe"
Write-Host "exe size : $((Get-Item $exe).Length) bytes"
Write-Host "sig size : $((Get-Item $sig).Length) bytes"
Write-Host "pubkey   : $($key.Substring(0,32))..."

Push-Location 'C:\Users\pc\Desktop\BlackRose\validation\msigcheck'
# cargo writes diagnostics on stderr; merge it into stdout and do NOT let
# PowerShell's error preference abort on it.
$ErrorActionPreference = 'Continue'
$out = & cargo run --quiet --release --offline -- `
    (Join-Path $v 'pub.key') $exe (Join-Path $v 'sig.txt') 2>&1
$rc = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
$out | ForEach-Object { Write-Host "  $_" }
Pop-Location

Write-Host "EXITCODE : $rc"
if ($rc -eq 0) { Write-Host 'RESULT: SIGNATURE VALID' -ForegroundColor Green }
else { Write-Host 'RESULT: SIGNATURE INVALID' -ForegroundColor Red }