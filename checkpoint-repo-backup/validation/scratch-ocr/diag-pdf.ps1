param([string]$PdfPath = 'C:\Users\pc\Desktop\BlackRose\validation\scratch-ocr\scanned.pdf')
$ErrorActionPreference = 'Stop'

[void][Windows.Data.Pdf.PdfDocument,Windows.Foundation,ContentType=WindowsRuntime]
[void][Windows.Storage.StorageFile,Windows.Foundation,ContentType=WindowsRuntime]
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($t, $rt) {
  $m = $asTaskGeneric.MakeGenericMethod($rt)
  $tk = $m.Invoke($null, @($t))
  try {
    $tk.Wait(-1) | Out-Null
  } catch {
    Write-Output ('WAIT_FAIL: ' + $_.Exception.InnerException.InnerException.Message)
    Write-Output ('HRESULT: 0x{0:X8}' -f $_.Exception.InnerException.InnerException.HResult)
    return
  }
  return $tk.Result
}

$f = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($pdfPath)) ([Windows.Storage.StorageFile])
Write-Output ('FILE_OK: ' + $f.Path)
$pdf = Await ([Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($f)) ([Windows.Data.Pdf.PdfDocument])
Write-Output ('PDF_NULL: ' + ($null -eq $pdf))
Write-Output ('ARR_COUNT: ' + @($pdf).Count)
for ($k = 0; $k -lt @($pdf).Count; $k++) {
  $e = @($pdf)[$k]
  if ($null -eq $e) { Write-Output ('ELEM' + $k + ': <null>') }
  else { Write-Output ('ELEM' + $k + ': ' + $e.GetType().FullName + ' :: [' + [string]$e + ']') }
}
# control: how many elements does the FIRST Await (StorageFile) return?
Write-Output ('FILE_COUNT: ' + @($f).Count)
for ($k = 0; $k -lt @($f).Count; $k++) {
  $e = @($f)[$k]
  if ($null -eq $e) { Write-Output ('FELEM' + $k + ': <null>') }
  else { Write-Output ('FELEM' + $k + ': ' + $e.GetType().FullName + ' :: [' + [string]$e + ']') }
}
if ($pdf -is [System.Array]) {
  $real = @($pdf) | Where-Object { $_ -is [Windows.Data.Pdf.PdfDocument] }
  Write-Output ('REAL_COUNT: ' + @($real).Count)
  if (@($real).Count -gt 0) { Write-Output ('REAL_PAGES: ' + @($real)[0].PageCount) }
}
Write-Output 'DIAG_DONE'


