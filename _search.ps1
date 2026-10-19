$root = 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/src'
Get-ChildItem $root -Recurse -Filter '*.ts' | ForEach-Object {
  $raw = Get-Content $_.FullName -Raw
  if ($raw -match 'aistate|aihistory|\.aistate') {
    Write-Output ("STATE: " + $_.FullName)
  }
  if ($raw -match 'ai_export|ai_import|exportState|importState') {
    Write-Output ("EI: " + $_.FullName)
  }
}
Write-Output "--- state file name refs (aistate writes) ---"
Get-ChildItem $root -Recurse -Filter '*.ts' | ForEach-Object {
  $lines = Get-Content $_.FullName
  for ($i=0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match 'aistate|aihistory') {
      Write-Output ($_.FullName.Replace($root,'') + ':' + ($i+1) + ': ' + $lines[$i].Trim())
    }
  }
}
