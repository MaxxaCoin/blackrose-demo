$dir='C:/Users/pc/Desktop/BlackRose/$ext'
if(Test-Path -LiteralPath $dir){ Remove-Item -LiteralPath $dir -Recurse -Force }
Remove-Item 'C:/Users/pc/Desktop/BlackRose/validation/check-extracted.ps1','C:/Users/pc/Desktop/BlackRose/validation/show-marker.ps1','C:/Users/pc/Desktop/BlackRose/validation/signed-0929.out' -Force -ErrorAction SilentlyContinue
Write-Host "cleanup done; ext exists: $(Test-Path -LiteralPath $dir)"
