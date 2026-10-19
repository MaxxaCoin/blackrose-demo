$files = @(
  'C:\Users\pc\Desktop\BlackRose\validation\x929-new\blackrose.mjs',
  'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\core\blackrose.mjs',
  'C:\Users\pc\Desktop\BlackRose\cline\blackrose\dist\blackrose.mjs'
)
$pats = @('MAX_CONTINUATIONS','CONTINUE_MS','TURN_BUDGET','turn budget reached','autoContinue','auto-continue')
foreach ($f in $files) {
  Write-Output ('=== ' + $f)
  $c = Get-Content $f -Raw
  foreach ($p in $pats) {
    $i = $c.IndexOf($p)
    if ($i -ge 0) {
      $start = [Math]::Max(0, $i-40)
      $len = [Math]::Min(110, $c.Length - $start)
      $ctx = ($c.Substring($start, $len) -replace "`r",'' -replace "`n",' ')
      Write-Output ("  [$p] ...$ctx...")
    } else {
      Write-Output ("  [$p] NOT FOUND")
    }
  }
}
