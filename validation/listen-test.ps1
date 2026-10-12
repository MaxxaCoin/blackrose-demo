# Probe the running BlackRose UI's /api/listen endpoint directly, bypassing
# the browser, so we can tell "the button is broken" from "the mic is dead".
param([int]$Port = 7591, [int]$Seconds = 4)
$ErrorActionPreference = 'Continue'
$body = @{ seconds = $Seconds } | ConvertTo-Json
try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/listen" -Method POST `
       -ContentType 'application/json' -Body $body -UseBasicParsing -TimeoutSec 40
  Write-Output ('HTTP ' + $r.StatusCode)
  Write-Output $r.Content
} catch {
  Write-Output ('ERR: ' + $_.Exception.Message)
}
