$x = 'C:\Program Files\7-Zip\7z.exe'
$setup = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\target\release\bundle\nsis\BlackRose_0.9.29_x64-setup.exe'
$dst = 'C:\Users\pc\Desktop\BlackRose\validation\x929-new'
Remove-Item $dst -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $dst -Force | Out-Null
& $x e -y -o"$dst" $setup 'core/blackrose.mjs' 2>&1 | Select-Object -Last 3
Write-Output '=== grep extracted mjs ==='
$m = Join-Path $dst 'blackrose.mjs'
Write-Output ('extracted exists: ' + (Test-Path $m))
foreach ($p in @('MAX_CONTINUATIONS','CONTINUE_MS','turn budget reached')) {
  $hit = Select-String -Path $m -Pattern $p -SimpleMatch -ErrorAction SilentlyContinue
  Write-Output ("  {0}: {1}" -f $p, ($(if($hit){$hit.Matches.Count}else{0})))
}
