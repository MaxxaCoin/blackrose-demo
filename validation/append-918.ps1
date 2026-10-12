$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)   # no BOM, like the original
$targets = @(
  'C:\Users\pc\Desktop\BlackRose\BLACKROSE_CHECKPOINT.txt',
  'C:\Users\pc\Desktop\BlackRose\cline\blackrose\docs\BLACKROSE_CHECKPOINT.txt'
)

$block = @'

========================================================================
RELEASE 0.9.18  (2026-10-04) - PUBLISHED, AND AUDIBLY CONFIRMED
========================================================================
Tag v0.9.18 on MaxxaCoin/BlackRose, marked Latest. Commits on
blackrose-source, all pushed to origin/main:

  b2a2d3c  a separate ringtone for approval and for task-done
  8c39f91  stop the S0/S1 sentinels corrupting rendered answers
  edf75ab  security: session write paths accepted an unvalidated id
  52acdfd  security: prototype-pollutable and type-confused cue preferences
  450fd6f  docs: correct the install allowlist comment
  6e6c88b  security: Authorization bearer headers were never redacted
  ff61dd6  chore(release): bump to 0.9.18

USER CONFIRMED ON THE INSTALLED BUILD (2026-10-04):
  - the approval chime is audible
  - the settings tab was inspected and is correct
This CLOSES the "chime has never been heard" item. Every earlier release
proved only that the command was AUTHORIZED; audibility could only ever be
confirmed by a human. Do not re-open this as unverified.

WHAT 0.9.18 ADDS
  - A "task done" cue, separate from the approval chime. Fires ONLY when a
    turn actually produced a final answer - never on a stopped, failed or
    disconnected turn, because a done-chime on failures trains the user to
    ignore the one that matters.
  - Independent ringtones: Classic / Gentle / Urgent / Bell, chosen
    separately for approval and for done, with "Preview both cues".
  - Fixed answers rendering as "approximately S1" instead of the real value.

THE S0/S1 BUG (rooted 2026-10-04, after two failed attempts)
  The data on disk was always correct. S0/S1 were renderRich's OWN stash
  sentinels: keep() wraps each generated tag in NUL+"S"+index+NUL so later
  regexes cannot match inside markup it just produced, and the result is
  assigned to innerHTML. The HTML parser is REQUIRED to rewrite U+0000 in the
  input stream to U+FFFD, so any sentinel reaching innerHTML came back as
  visible garbage, replacing the value ("2.01%") with "S1".
  Sentinels are now Private Use Area chars (U+E000/U+E001), which pass through
  untouched, plus a final sweep that removes any NUL/FFFD-wrapped S<digits>.
  It cannot eat prose - "matrix S1 and S2 rows" is verified to survive.

SECURITY (found by attacking the code, not reading it)
  - Authorization: Bearer <token> was NEVER redacted. "authorization" was
    missing from the assigned_secret key list AND the value charset could not
    cross the space in "Bearer ". The most common way a credential is written
    down, flowing into logs, disk and model context.
  - Session ids unvalidated on the WRITE path. Not reachable today (the web
    route validates on load); fixed as defence in depth.
  - Cue preferences prototype-pollutable and type-confused.

VERIFIED FOR THE RELEASE
  - signature VALID; trusted comment names BlackRose_0.9.18_x64-setup.exe
  - uploaded .exe sha256 7cd68b3d...1591c1 matches local byte-for-byte
  - live latest.json HTTP 200, 755 B, NO BOM, version 0.9.18
  - payload strings confirmed in the SHIPPED binaries (allow-done-chime,
    done_chime, uE000S, CUES[cue + 'Tone'], synthCue, this is a stale core)
  - smoke 221 PASS / 0 FAIL, unit 51 / 0, scan:secrets clean,
    scan:history clean across 170 commits, npm audit 0, tsc + cargo check clean

  Search for STRING LITERALS when verifying a stripped release binary.
  Function names do not survive - searching BlackRose.exe for "fn listener_pid"
  returns a false negative and looks like a missing fix.

UPLOAD SEQUENCING (learned the hard way on 0.9.17)
  Upload the 24 MB installer into a DRAFT, verify its sha256, THEN publish.
  On 0.9.17 two HTTP 408s left the release live without its installer, so the
  updater advertised a dead download for several minutes. On 0.9.18 the assets
  were all confirmed in the draft first, then published in one step.

STILL OPEN
  - Multi-device .aistate sync (backlog 5) - needs a second real machine.
  - U+FFFD around S0/S1: the UI cause is fixed, but the U+FFFD glyphs
    themselves were never reproduced in state and remain unexplained. The
    related PowerShell 5.1 ANSI-codepage trap is real and documented above.
  - Not yet reviewed: src/llm route/key-pool, src/schedule timezone logic,
    MCP/job buffer bounds, Rust process-kill paths, and hostile input to the
    PDF/DOCX/XLSX parsers beyond zip-slip.
'@

foreach ($t in $targets) {
    $before = [IO.File]::ReadAllText($t, $utf8)
    if ($before -match 'RELEASE 0\.9\.18') { Write-Host "  skip (present): $t"; continue }
    [IO.File]::WriteAllText($t, $before + $block, $utf8)
    $after = [IO.File]::ReadAllText($t, $utf8)
    $bytes = [IO.File]::ReadAllBytes($t)
    $lines = ([regex]::Matches($after, "`n")).Count + 1
    Write-Host ("  {0}: {1} lines, {2} bytes, bom={3}, mojibake={4}" -f `
        (Split-Path $t -Leaf), $lines, $bytes.Length,
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF),
        ($after.Contains([char]0xC3) -and $after.Contains([char]0x00A2)))
}
