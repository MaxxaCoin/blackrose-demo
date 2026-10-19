$ErrorActionPreference = 'Stop'
$v     = 'C:\Users\pc\Desktop\BlackRose\validation'
$conf  = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\tauri.conf.json'
$nsis  = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\target\release\bundle\nsis'
$exe   = Join-Path $nsis 'BlackRose_0.9.29_x64-setup.exe'
$sig   = "$exe.sig"

# --- public key: decode outer layer, then take the bare key line ---
$upd = (Get-Content $conf -Raw | ConvertFrom-Json).plugins.updater
$keyB64 = $upd.pubkey; if (-not $keyB64) { $keyB64 = $upd.pubKey }
$keyFileText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($keyB64.Trim()))
$bareKey = ($keyFileText -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim()
if ($bareKey.Length -ne 56) { throw "bare key is $($bareKey.Length) chars, expected 56" }
[IO.File]::WriteAllText((Join-Path $v 'pub.key'), $bareKey, [Text.Encoding]::ASCII)

# --- signature: decode outer layer to get minisign text ---
$sigB64 = (Get-Content $sig -Raw).Trim()
$sigText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($sigB64))
[IO.File]::WriteAllText((Join-Path $v 'sig.txt'), $sigText, [Text.Encoding]::ASCII)

Write-Host "exe        : $((Get-Item $exe).Length) bytes"
Write-Host "sig (raw)  : $((Get-Item $sig).Length) bytes"
Write-Host "bare key   : $bareKey"
Write-Host "sig lines  : $(($sigText -split "`r?`n" | Where-Object { $_.Trim() }).Count)"
Write-Host '--- verifying ---'

Push-Location '.'
try {
  Push-Location 'C:\Users\pc\Desktop\BlackRose\validation\msigcheck'
  $ErrorActionPreference = 'Continue'
  $out = & cargo run --quiet --release --offline -- `
      (Join-Path $v 'pub.key') $exe (Join-Path $v 'sig.txt') 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  $out | ForEach-Object { Write-Host "  $_" }
} finally { Pop-Location }

Write-Host "EXITCODE   : $rc"
if ($rc -eq 0) { Write-Host 'RESULT: SIGNATURE VALID' -ForegroundColor Green }
else           { Write-Host 'RESULT: SIGNATURE INVALID' -ForegroundColor Red }

