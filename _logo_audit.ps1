$ErrorActionPreference = 'SilentlyContinue'
Write-Output '=== Downloads logo ==='
$logo = 'C:\Users\pc\Downloads\blackrose_logo.png'
if (Test-Path $logo) { $i=Get-Item $logo; Write-Output ("  exists size={0} modified={1}" -f $i.Length, $i.LastWriteTime) } else { Write-Output '  NOT FOUND' }

Write-Output ''
Write-Output '=== tauri dir top-level ==='
Get-ChildItem -Force 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/desktop/tauri' | Select-Object Mode,Length,LastWriteTime,Name | Format-Table -Auto

Write-Output ''
Write-Output '=== tauri.conf.json / tauri directory ==='
$confs = Get-ChildItem -Force 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/desktop/tauri' -Filter '*.json'
$confs | Select-Object FullName,Length,LastWriteTime | Format-Table -Auto

Write-Output ''
Write-Output '=== icons (only top-level, avoid target) ==='
Get-ChildItem -Force 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/desktop/tauri/icons' -ErrorAction SilentlyContinue | Select-Object Mode,Length,Name | Format-Table -Auto
