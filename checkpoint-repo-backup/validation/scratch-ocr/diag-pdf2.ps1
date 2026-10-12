param([string]$PdfPath = 'C:\Users\pc\Desktop\BlackRose\validation\scratch-ocr\scanned2.pdf')
$ErrorActionPreference = 'Stop'

[void][Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Globalization.Language,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Graphics.Imaging.BitmapDecoder,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Storage.StorageFile,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Data.Pdf.PdfDocument,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Storage.Streams.InMemoryRandomAccessStream,Windows.Foundation,ContentType=WindowsRuntime]
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$at = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($t, $rt) {
  $m = $at.MakeGenericMethod($rt)
  $tk = $m.Invoke($null, @($t))
  $tk.Wait(-1) | Out-Null
  return $tk.Result
}
$aa = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' })[0]
$en = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if (-not $en) { $en = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage([Windows.Globalization.Language]::new('en-US')) }
if (-not $en) { throw 'no-ocr-engine' }

$f = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($PdfPath)) ([Windows.Storage.StorageFile])
$pdf = Await ([Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($f)) ([Windows.Data.Pdf.PdfDocument])
Write-Output ('PAGES=' + $pdf.PageCount)
$opts = $null
$pg0 = $pdf.GetPage(0)
Write-Output ('PAGESIZE=' + $pg0.Size.Width + 'x' + $pg0.Size.Height)
$pg0.Dispose()
$n = [Math]::Min($pdf.PageCount, 5)
for ($i = 0; $i -lt $n; $i++) {
  $pg = $pdf.GetPage($i)
  $st = [Windows.Storage.Streams.InMemoryRandomAccessStream]::new()
  $tk = $aa.Invoke($null, @($pg.RenderToStreamAsync($st)))
  $tk.Wait()
  Write-Output ('RENDER' + $i + '_BYTES=' + $st.Size)
  $pg.Dispose()
  $dec = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($st)) ([Windows.Graphics.Imaging.BitmapDecoder])
  $sb = Await ($dec.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8, [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied)) ([Windows.Graphics.Imaging.SoftwareBitmap])
  $res = Await ($en.RecognizeAsync($sb)) ([Windows.Media.Ocr.OcrResult])
  $st.Dispose(); $sb.Dispose()
  Write-Output ('PAGE' + $i + '_LINES=' + $res.Lines.Count)
  Write-Output ('PAGE' + $i + '_TEXT: ' + $res.Text)
}
Write-Output 'DIAG2_DONE'
