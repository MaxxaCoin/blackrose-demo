$htmlPath = 'C:\Users\pc\Desktop\BlackRose\validation\scratch-ocr\scanned.html'
$pdfPath = 'C:\Users\pc\Desktop\BlackRose\validation\scratch-ocr\scanned2.pdf'
Set-Content -Path $htmlPath -Encoding UTF8 -Value @'
<!doctype html><html><head><style>html,body{margin:0;padding:0}img{display:block;width:100vw}</style></head>
<body><img src="test-ocr.png"></body></html>
'@
$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
if (-not (Test-Path $edge)) { $edge = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe' }
Remove-Item $pdfPath -ErrorAction SilentlyContinue
& $edge --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="$pdfPath" "file:///$($htmlPath -replace '\\','/')" 2>$null | Out-Null
Start-Sleep -Seconds 3
if (Test-Path $pdfPath) { Write-Output ('SCANNED2_PDF: ' + (Get-Item $pdfPath).Length + ' bytes') } else { Write-Output 'SCANNED2_PDF: FAILED' }
