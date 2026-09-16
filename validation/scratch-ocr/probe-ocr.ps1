$ErrorActionPreference = 'Stop'
$dir = 'C:\Users\pc\Desktop\BlackRose\validation\scratch-ocr'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

Add-Type -AssemblyName System.Drawing

# --- 1) generate a test image with known text ---
$imgPath = Join-Path $dir 'test-ocr.png'
$bmp = New-Object System.Drawing.Bitmap 950, 320
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.Clear([System.Drawing.Color]::White)
$font = New-Object System.Drawing.Font('Segoe UI', 34)
$b = [System.Drawing.Brushes]::Black
$g.DrawString('BLACKROSE OCR PROBE 2026', $font, $b, 20, 25)
$g.DrawString('Line two: hello from Windows OCR', $font, $b, 20, 115)
$g.DrawString('Third: 12345 abztest release', $font, $b, 20, 205)
$g.Dispose()
$bmp.Save($imgPath, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output ('IMAGE: ' + $imgPath)

# --- 2) WinRT OCR over the image ---
[void][Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Globalization.Language,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Graphics.Imaging.BitmapDecoder,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Storage.StorageFile,Windows.Foundation,ContentType=WindowsRuntime]

Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($t, $rt) {
  $m = $asTaskGeneric.MakeGenericMethod($rt)
  $tk = $m.Invoke($null, @($t))
  $tk.Wait(-1) | Out-Null
  return $tk.Result
}

$langs = [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages
Write-Output ('OCR_LANGS: ' + (($langs | ForEach-Object { $_.LanguageTag }) -join ','))

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if (-not $engine) { $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage([Windows.Globalization.Language]::new('en-US')) }
if (-not $engine) { throw 'No OcrEngine available on this machine' }
Write-Output ('ENGINE_LANG: ' + $engine.RecognizerLanguage.LanguageTag)
Write-Output ('MAX_DIM: ' + $engine.MaxImageDimension)

$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($imgPath)) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$sbmp = Await ($decoder.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8, [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied)) ([Windows.Graphics.Imaging.SoftwareBitmap])
$ocr = Await ($engine.RecognizeAsync($sbmp)) ([Windows.Media.Ocr.OcrResult])
$stream.Dispose(); $sbmp.Dispose()
Write-Output ('OCR_LINES: ' + $ocr.Lines.Count)
Write-Output 'OCR_TEXT:'
Write-Output $ocr.Text

# --- 3) Windows.Data.Pdf availability (for scanned-PDF rendering) ---
[void][Windows.Data.Pdf.PdfDocument,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Storage.Streams.InMemoryRandomAccessStream,Windows.Foundation,ContentType=WindowsRuntime]
Write-Output 'PDF_API: OK'
Write-Output 'PROBE_DONE'
