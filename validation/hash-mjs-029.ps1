$files = @(
  'C:\Users\pc\Desktop\BlackRose\validation\x929-new\blackrose.mjs',
  'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\core\blackrose.mjs',
  'C:\Users\pc\Desktop\BlackRose\cline\blackrose\dist\blackrose.mjs'
)
foreach ($f in $files) {
  $h = (Get-FileHash $f -Algorithm SHA256).Hash
  $sz = (Get-Item $f).Length
  Write-Output ("{0}  {1}  {2}" -f $sz, $h, $f)
}
Write-Output '=== MAX_CONTINUATIONS value line ==='
$c = Get-Content (Join-Path 'C:\Users\pc\Desktop\BlackRose\validation\x929-new\blackrose.mjs') -Raw
$i = $c.IndexOf('MAX_CONTINUATIONS')
if ($i -ge 0) { Write-Output $c.Substring($i, 60) }
