$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$p = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\ui\web\assets.ts'
$t = [IO.File]::ReadAllText($p, $utf8)

function Swap([string]$find, [string]$repl, [string]$label) {
    $n = ([regex]::Matches($script:t, [regex]::Escape($find))).Count
    if ($n -ne 1) { throw "$label : expected 1 occurrence, found $n" }
    $script:t = $script:t.Replace($find, $repl)
    Write-Host "  patched: $label"
}

# 1. the sentinel itself
Swap 'const keep = (html) => { stash.push(html); return ''\u0000S'' + (stash.length - 1) + ''\u0000''; };' `
     "// Sentinels are Private Use Area characters, NOT NUL. This is the fix for the" `
     'keep()'

# 2. the block-level stashed-element test. NOTE the DOUBLE backslashes: this JS
# lives inside a TS template literal, so `\\s` in source becomes `\s` in the page.
Swap '/^\\s*\\u0000S\\d+\\u0000\\s*$/' '/^\\s*\\uE000S\\d+\\uE001\\s*$/' 'block test'

# 3. the restore, plus a safety net that makes a leak impossible
$restoreOld = 'out.replace(/\\u0000S(\\d+)\\u0000/g, (m, i) => stash[Number(i)] || '''')'
$restoreNew = @'
out.replace(/\\uE000S(\\d+)\\uE001/g, (m, i) => stash[Number(i)] || '');
  // SAFETY NET. A stash sentinel must never reach innerHTML: the HTML parser
  // rewrites U+0000 to U+FFFD, so a leak shows the user a literal "S1" wrapped in
  // replacement characters, which is exactly the corruption this replaced. This
  // matches only NUL/FFFD-wrapped S<digits>, a shape real prose cannot produce,
  // so it cannot eat legitimate text - it just guarantees the user never sees a
  // sentinel again, whatever path leaked it.
  out = out.replace(/[\\u0000\\uFFFD]S\\d+[\\u0000\\uFFFD]/g, '');
'@
Swap $restoreOld $restoreNew 'restore + safety net'

[IO.File]::WriteAllText($p, $t, $utf8)
Write-Host "written"