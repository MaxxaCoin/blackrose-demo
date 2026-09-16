$ErrorActionPreference = 'Stop'
$dir = 'C:\Users\pc\Desktop\BlackRose\validation\scratch-ocr'

# 1) render sentinel text to JPEG (this becomes the only "content" of the PDF)
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap 1100, 340
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.Clear([System.Drawing.Color]::White)
$f = New-Object System.Drawing.Font('Segoe UI', 30)
$g.DrawString('SCANNED PDF OCR TARGET 77', $f, [System.Drawing.Brushes]::Black, 30, 40)
$g.DrawString('fallback proof: learn_pdf via ocr', $f, [System.Drawing.Brushes]::Black, 30, 150)
$g.Dispose()
$ms = New-Object System.IO.MemoryStream
$codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
$encParams = New-Object System.Drawing.Imaging.EncoderParameters 1
$encParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]90)
$bmp.Save($ms, $codec, $encParams)
$bmp.Dispose()
$jpeg = $ms.ToArray()
$ms.Dispose()
$imgW = 1100
$imgH = 340

# 2) build a minimal single-page PDF embedding the JPEG (DCTDecode), no text layer
$out = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter($out)
function WStr([System.IO.BinaryWriter]$bw, [string]$s) { $bw.Write([System.Text.Encoding]::ASCII.GetBytes($s)) }
function ObjStart([System.IO.BinaryWriter]$bw) { return [int]$bw.BaseStream.Position }

WStr $w "%PDF-1.4`n"
$o1 = ObjStart $w; WStr $w "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n"
$o2 = ObjStart $w; WStr $w "2 0 obj`n<< /Type /Pages /Kids [3 0 R] /Count 1 >>`nendobj`n"
$o3 = ObjStart $w; WStr $w "3 0 obj`n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im0 4 0 R >> /ProcSet [/PDF /ImageC] >> /Contents 5 0 R >>`nendobj`n"
$o4 = ObjStart $w
WStr $w "4 0 obj`n<< /Type /XObject /Subtype /Image /Width $imgW /Height $imgH /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length $($jpeg.Length) >>`nstream`n"
$w.Write($jpeg)
WStr $w "`nendstream`nendobj`n"
$drawH = [math]::Round(612.0 * $imgH / $imgW, 2)
$content = "q 612 0 0 $drawH 0 400 cm /Im0 Do Q"
$o5 = ObjStart $w
WStr $w "5 0 obj`n<< /Length $($content.Length) >>`nstream`n$content`nendstream`nendobj`n"
$xref = ObjStart $w
WStr $w "xref`n0 6`n0000000000 65535 f `n"
foreach ($off in @($o1, $o2, $o3, $o4, $o5)) { WStr $w ('{0:d10} 00000 n `n' -f $off) }
WStr $w "trailer`n<< /Size 6 /Root 1 0 R >>`nstartxref`n$xref`n%%EOF`n"
$pdfPath = Join-Path $dir 'scanned.pdf'
[System.IO.File]::WriteAllBytes($pdfPath, $out.ToArray())
$w.Dispose()

Write-Output ('PDF: ' + $pdfPath + ' (' + (Get-Item $pdfPath).Length + ' bytes, jpeg ' + $jpeg.Length + ')')
Write-Output 'PDFBUILD_DONE'
