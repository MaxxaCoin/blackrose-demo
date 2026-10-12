$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)   # no BOM, like the original
$path = 'C:\Users\pc\Desktop\BlackRose\BLACKROSE_CHECKPOINT.txt'
$docs = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\docs\BLACKROSE_CHECKPOINT.txt'

# CRITICAL: read/write with explicit UTF8. PowerShell 5.1's Get-Content defaults
# to the ANSI codepage, which double-encodes every non-ASCII char on rewrite.
# That already corrupted this file once; never use bare Get-Content here.

$block = @'

========================================================================
RELEASE 0.9.16  (2026-10-03) - PUBLISHED AND VERIFIED
========================================================================
Tag v0.9.16 on MaxxaCoin/BlackRose, marked Latest.

Commits (blackrose-source, all pushed to origin/main):
  6319a12  fix(desktop): authorize the approval chime for the remote origin
  ee09e04  chore(release): bump 0.9.15 -> 0.9.16
  be330c8  fix(release): de-hardcode 0.9.15 from the signer

THE BUG: the approval chime was silent for three stacked reasons.
  1. frontend used the wrong IPC entry point for the loopback origin
  2. "approval_chime" missing from the generated ACL (desktop/tauri/build.rs)
  3. "allow-approval-chime" missing from the remote-updater.json capability
Fixing only the capability was not enough - all three were required.

VERIFIED (rerunnable: validation/verify-sig916.ps1):
  - signature VALID (minisign; trusted comment names
    BlackRose_0.9.16_x64-setup.exe; artifact 25778368 bytes)
  - uploaded .exe sha256 db0e080e...d8a2d9a matches local byte-for-byte
  - live .sig identical to local
  - payload strings present in the SHIPPED installer:
      BlackRose.exe    allow-approval-chime, PlaySoundW, "2-tone alert ok"
      blackrose.mjs    __TAURI_INTERNALS__.invoke, "native approval_chime failed"
  - live latest.json: HTTP 200, 837 bytes, NO BOM, version 0.9.16
  - live installer + sig: HTTP 200

GOTCHA WORTH KEEPING: sign-release.ps1 had four hardcoded 0.9.15 literals.
One was the .sig VERIFICATION path, so a 0.9.16 run would have silently
validated the 0.9.15 artifact while reporting 0.9.16. Fixed in be330c8.

ENCODING TRAP (cost real time, 2026-10-03): PowerShell 5.1 Get-Content
defaults to the ANSI codepage. Reading a UTF-8 file with it and writing it
back with WriteAllLines double-encodes every non-ASCII char: an em-dash
becomes mojibake. Use [IO.File]::ReadAllText/WriteAllText with an explicit
UTF8Encoding($false) for any non-ASCII file here.

STILL OPEN - DO NOT CALL 0.9.16 FULLY VALIDATED:
  - THE CHIME HAS NEVER BEEN HEARD. Authorization is proven end to end;
    audibility is NOT. Install it, trigger an approval prompt, and confirm
    sound while the window is minimized/backgrounded.
  - U+FFFD replacement glyphs around S0/S1/S2 remain unrooted. Data on disk
    is intact; display only. NOT fixed in this release.
  - validation/signed-0916.out is genuinely double-encoded on disk (reads as
    U+0393 where U+2713 check should be). Same family as the U+FFFD issue.
'@

foreach ($target in @($path, $docs)) {
    $before = [IO.File]::ReadAllText($target, $utf8)
    if ($before -match 'RELEASE 0\.9\.16') { Write-Host "  skip (already present): $target"; continue }
    [IO.File]::WriteAllText($target, $before + $block, $utf8)
    $after  = [IO.File]::ReadAllText($target, $utf8)
    $bytes  = [IO.File]::ReadAllBytes($target)
    Write-Host ("  {0}  bytes={1}  bom={2}  badchars={3}" -f `
        (Split-Path $target -Parent | Split-Path -Leaf), $bytes.Length,
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF),
        ($after.Contains([char]0xC3) -and $after.Contains([char]0x00A2)))
}