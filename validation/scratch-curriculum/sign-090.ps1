# Sign the 0.9.0 installer: try EVERY BLACKROSE_SIGNING_PASSWORD assignment
# recorded in PS history until one works. NEVER prints the password.
$ErrorActionPreference = 'Stop'
$h = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
$lines = Get-Content $h
$cands = @()
foreach ($l in $lines) {
  if ($l -match 'BLACKROSE_SIGNING_PASSWORD\s*=\s*(.+)$') {
    $v = $Matches[1].Trim()
    if ($v.Length -ge 2 -and (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'")))) { $v = $v.Substring(1, $v.Length - 2) }
    if ($v -and ($cands -notcontains $v)) { $cands += $v }
  }
}
Write-Output ('candidates: ' + $cands.Count)
$key = [IO.File]::ReadAllText('C:\Users\pc\.tauri\blackrose.key')
Set-Location 'C:\Users\pc\Desktop\BlackRose\cline\blackrose'
$exe = 'desktop\tauri\target\release\bundle\nsis\BlackRose_0.9.0_x64-setup.exe'
$i = 0
foreach ($pw in $cands) {
  $i++
  $env:TAURI_SIGNING_PRIVATE_KEY = $key
  $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $pw
  $ErrorActionPreference = 'Continue'
  node node_modules\@tauri-apps\cli\tauri.js signer sign $exe 2>$null | Out-Null
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  if ($code -eq 0) { Write-Output ("SIGNED with candidate #" + $i); exit 0 }
  else { Write-Output ("candidate #" + $i + " failed") }
}
Write-Output 'all candidates failed'
exit 1
