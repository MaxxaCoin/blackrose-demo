$htmlPath = 'C:\Users\pc\Desktop\BlackRose\validation\scratch-ocr\control.html'
$pdfPath = 'C:\Users\pc\Desktop\BlackRose\validation\scratch-ocr\control.pdf'
Set-Content -Path $htmlPath -Encoding UTF8 -Value @'
<!doctype html><html><head><style>body{font-family:Segoe UI;font-size:42px}</style></head>
<body><h1>CONTROL PDF OCR TARGET 55</h1><p>edge print to pdf pipeline test</p></body></html>
'@
$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
if (-not (Test-Path $edge)) { $edge = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe' }
Remove-Item $pdfPath -ErrorAction SilentlyContinue
& $edge --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="$pdfPath" "file:///$($htmlPath -replace '\\','/')" 2>$null | Out-Null
Start-Sleep -Seconds 3
if (Test-Path $pdfPath) { Write-Output ('CONTROL_PDF: ' + (Get-Item $pdfPath).Length + ' bytes') } else { Write-Output 'CONTROL_PDF: FAILED' }
