$ErrorActionPreference = 'Stop'
$repo = 'MaxxaCoin/BlackRose'
$dl = 'C:\Users\pc\Desktop\BlackRose\validation\rel029-download'
New-Item -ItemType Directory -Path $dl -Force | Out-Null
$files = @('BlackRose_0.9.29_x64-setup.exe','BlackRose_0.9.29_x64-setup.exe.sig','latest.json')
foreach ($f in $files) {
  Write-Output "=== downloading $f ==="
  gh release download v0.9.29 --repo $repo --pattern $f --dir $dl 2>&1
  $local = Join-Path $dl $f
  if (Test-Path $local) {
    Write-Output ("  sha256: " + (Get-FileHash $local -Algorithm SHA256).Hash)
    Write-Output ("  size  : " + (Get-Item $local).Length)
  } else {
    Write-Output '  DOWNLOAD FAILED'
  }
}
