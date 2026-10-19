$ErrorActionPreference = 'Continue'
Write-Output '=== Python Pillow check ==='
python -c "import PIL; print('Pillow', PIL.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) { Write-Output '  Pillow NOT installed' }

Write-Output ''
Write-Output '=== Can we read the current icon.ico well? ==='
Write-Output '  (already know: 4 embedded images, size 285478)'

Write-Output ''
Write-Output '=== Where does the window icon get set in Rust code? ==='
$src = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\src'
Get-ChildItem -Force $src -Recurse -ErrorAction SilentlyContinue | Select-Object Mode,Length,Name,FullName | Format-Table -Auto
