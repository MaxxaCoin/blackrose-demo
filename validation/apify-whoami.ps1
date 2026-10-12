# List recent runs of the actor to get a live runId + datasetId, then find
# which dataset-items query works. Never echoes the token.
$ErrorActionPreference = 'Continue'
$tok = ([IO.File]::ReadAllText('C:\Users\pc\.cline\data\sessions\session_1790588551324_d78af\user-attachments\35f10fd8-d5f0-46b3-9ccf-d72375f0e554-apify_api_key.txt')).Trim()
$t = [uri]::EscapeDataString($tok)

$list = Invoke-RestMethod -Uri "https://api.apify.com/v2/acts/apify~instagram-scraper/runs?limit=5&desc=1&token=$t" -TimeoutSec 30
Write-Output ('recent runs: ' + @($list.data.items).Count)
$run = @($list.data.items) | Where-Object { $_.status -eq 'SUCCEEDED' } | Select-Object -First 1
if (-not $run) { Write-Output 'no succeeded run'; exit 1 }
Write-Output ('run ' + $run.id + ' status ' + $run.status)
Write-Output ('  defaultDatasetId: ' + $run.defaultDatasetId)

$ds = $run.defaultDatasetId
foreach ($q in @('?clean=true&format=json', '?format=json', '?clean=true', '')) {
  try {
    $r = Invoke-RestMethod -Uri ("https://api.apify.com/v2/datasets/$ds/items" + $q + "&token=$t") -TimeoutSec 30
    $n = @($r).Count
    Write-Output ("OK   '" + $q + "' -> $n item(s)")
    if ($n -gt 0) { Write-Output ('     first caption: ' + (String(@($r)[0].caption).Substring(0,[Math]::Min(70,(String(@($r)[0].caption)).Length)))) }
  } catch {
    Write-Output ("FAIL '" + $q + "' -> " + $_.Exception.Message.Substring(0,[Math]::Min(90,$_.Exception.Message.Length)))
  }
}
