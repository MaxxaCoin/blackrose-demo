$ErrorActionPreference = 'Continue'
Write-Output '=== tauri/ui contents ==='
$ui = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\ui'
Get-ChildItem -Force $ui -Recurse -ErrorAction SilentlyContinue | Select-Object Mode,Length,Name,FullName | Format-Table -Auto

Write-Output '=== scripts dir ==='
Get-ChildItem -Force 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/scripts' -ErrorAction SilentlyContinue | Select-Object Mode,Length,Name | Format-Table -Auto

Write-Output '=== built EXE location ==='
Get-ChildItem -Path 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/desktop/tauri/target/release' -Filter 'BlackRose.exe' -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Format-Table -Auto
Get-ChildItem -Path 'C:/Users/pc/AppData/Local/BlackRose' -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Format-Table -Auto

Write-Output '=== current EXE exported icon (does it reference icon.ico)? check build config ==='
Write-Output '  tauri.conf.json bundle.icon = icons/icon.ico'
