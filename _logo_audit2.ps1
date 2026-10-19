$ErrorActionPreference = 'Continue'

Write-Output '=== Tool availability ==='
foreach ($t in @('magick','ffmpeg','python')) {
  $cmd = Get-Command $t -ErrorAction SilentlyContinue
  if ($cmd) { Write-Output ("  {0} -> {1}" -f $t, $cmd.Source) } else { Write-Output ("  {0} -> (not found)" -f $t) }
}

Write-Output ''
Write-Output '=== UI logo/brand files ==='
$ui = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\ui'
if (Test-Path $ui) {
  Get-ChildItem -Force $ui -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'logo|icon|brand' -or $_.Extension -in '.png','.svg','.ico' } |
    Select-Object FullName,Length | Format-Table -Auto
} else {
  Write-Output '  tauri/ui does not exist'
}

Write-Output ''
Write-Output '=== ICO current content (first bytes) ==='
$ico = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\icons\icon.ico'
if (Test-Path $ico) {
  $bytes = [System.IO.File]::ReadAllBytes($ico)
  Write-Output ("  ico size={0}  header bytes 0-3: {1:x2} {2:x2} {3:x2} {4:x2}" -f $bytes.Length, $bytes[0], $bytes[1], $bytes[2], $bytes[3])
  # ICO header: reserved(2) type(2) count(2) then dir entries
  $count = $bytes[4] -bor ($bytes[5] -shl 8)
  Write-Output ("  embedded images in ico: {0}" -f $count)
}

Write-Output ''
Write-Output '=== PNG header ==='
$png = 'C:\Users\pc\Downloads\blackrose_logo.png'
if (Test-Path $png) {
  $b = [System.IO.File]::ReadAllBytes($png)
  Write-Output ("  png size={0}" -f $b.Length)
  Write-Output ("  header: {0} {1} {2} {3}" -f $b[0], $b[1], $b[2], $b[3])
  # PNG IHDR: width(4) height(4) bitdepth(1) colortype(1)
  if ($b[1] -eq 0x50 -and $b[2] -eq 0x4E) {
    $w = [uint32]($b[16] -shl 24) -bor ($b[17] -shl 16) -bor ($b[18] -shl 8) -bor $b[19]
    $h = [uint32]($b[20] -shl 24) -bor ($b[21] -shl 16) -bor ($b[22] -shl 8) -bor $b[23]
    $bd = $b[24]; $ct = $b[25]
    Write-Output ("  png  {0}x{1}  bitdepth={2} colortype={3}" -f $w, $h, $bd, $ct)
  }
}

Write-Output ''
Write-Output '=== gen dir (tauri icons copied out?) ==='
Get-ChildItem -Force 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/desktop/tauri/gen' -ErrorAction SilentlyContinue | Select-Object Mode,Name | Format-Table -Auto
