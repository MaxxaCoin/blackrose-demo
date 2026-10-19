$ErrorActionPreference = 'Continue'
$exe = 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/desktop/tauri/target/release/bundle/nsis/BlackRose_0.9.30_x64-setup.exe'
$local = (Get-FileHash $exe -Algorithm SHA256).Hash
Write-Host "local installer SHA: $local"
Write-Host '--- remote asset digests ---'
$json = & gh api repos/MaxxaCoin/BlackRose/releases --jq '.[0].assets' 2>&1 | Out-String
$assets = $json | ConvertFrom-Json
foreach ($a in $assets) { Write-Host ($a.name + ' | ' + $a.size + ' | ' + ($a.digest)) }

cd 'C:/Users/pc/Desktop/BlackRose/cline/blackrose'
$exe = 'desktop/tauri/target/release/bundle/nsis/BlackRose_0.9.30_x64-setup.exe'
$local = (Get-FileHash $exe -Algorithm SHA256).Hash
Write-Host "local installer SHA: $local"
$assets = gh release view v0.9.30 --repo MaxxaCoin/BlackRose --json assets -q '.assets[] | "\(.name) | \(.size) | \(.digest)"' 2>&1
$assets | ForEach-Object { Write-Host $_ }
