$ErrorActionPreference = 'Stop'
$path = 'C:\Users\pc\Desktop\BlackRose\BLACKROSE_CHECKPOINT.txt'
$all  = Get-Content $path

# Ground truth from inspection:
#   L1398 "  - Free-model availability on OpenRouter changes daily; if the default"
#   L1399..L1438  <- my 40-line block, which displaced the continuation of L1398
# Block runs to EOF, so restoring the displaced line and appending the block at
# EOF leaves the original tail intact above it.
$orig = '    model 404s/429s persistently, re-run the models probe and pick a new'
[string[]]$block = $all[1398..1437]
if ($block[1] -notmatch 'RELEASE 0\.9\.16') { throw "block start mismatch: $($block[1])" }
if ($block[-1] -notmatch 'investigate together') { throw "block end mismatch: $($block[-1])" }
Write-Host "block ok: $($block.Count) lines, '$($block[1])' .. '$($block[-1])'"

[string[]]$new = @()
$new += $all[0..1397]          # through L1398 (0-based 0..1397)
$new += $orig                   # restore the displaced continuation
$new += $all[0..0] | Out-Null  # no-op guard
$new = $new[0..($new.Count-1)]
$new += ''                      # blank separator
$new += $block                  # release record at EOF

[IO.File]::WriteAllLines($path, $new, (New-Object System.Text.UTF8Encoding($false)))
$chk = Get-Content $path
Write-Host "old lines: $($all.Count)   new lines: $($chk.Count)"
Write-Host "L1398: $($chk[1397])"
Write-Host "L1399: $($chk[1398])"
Write-Host "L1400: $($chk[1399])"
Write-Host "last : $($chk[-1])"