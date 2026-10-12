$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$path = 'C:\Users\pc\Desktop\BlackRose\cline\blackrose\desktop\tauri\src\main.rs'

# Split on newlines WITHOUT letting PowerShell re-encode anything.
$text = [IO.File]::ReadAllText($path, $utf8)
$lines = [System.Collections.Generic.List[string]]::new()
$lines.AddRange([string[]]($text -split "`r?`n"))

# 1-based 390..434 is the old approval_chime (attribute through closing brace).
$start = 389; $end = 433
if ($lines[$start] -ne '#[tauri::command]') { throw "start mismatch: $($lines[$start])" }
if ($lines[$start + 1] -notmatch 'fn approval_chime') { throw "fn mismatch: $($lines[$start + 1])" }
if ($lines[$end] -ne '}') { throw "end mismatch: [$($lines[$end])]" }
Write-Host "verified span L$($start + 1)..L$($end + 1)"

$new = @'
#[tauri::command]
fn approval_chime(tone: Option<String>) -> Result<(), String> {
    play_cue("approval", tone.as_deref().unwrap_or("classic"))
}

/// "Task finished" cue. A separate command rather than a flag on approval_chime so
/// each notification keeps a name that says what it means, and so the ACL grants
/// them independently.
#[tauri::command]
fn done_chime(tone: Option<String>) -> Result<(), String> {
    play_cue("done", tone.as_deref().unwrap_or("classic"))
}

/// Shared native player for every notification cue.
///
/// SND_MEMORY plays a WAV buffer, so nothing is looked up on disk and no external
/// asset can be missing. Synchronous is safe because the longest cue is ~520 ms,
/// so the worst case is that the command returns half a second late, never a
/// hang. Only this IPC call waits; the main thread is never blocked.
///
/// The real result is reported rather than always returning Ok(). A cue that
/// cannot say why it is silent is exactly how this went unnoticed through four
/// releases: the command "succeeded", the page saw no error, and no sound came.
#[cfg(target_os = "windows")]
fn play_cue(cue: &str, tone: &str) -> Result<(), String> {
    #[link(name = "winmm")]
    extern "system" {
        fn PlaySoundW(psz: *const u16, hmod: *mut core::ffi::c_void, fdw: u32) -> i32;
    }
    const SND_SYNC: u32 = 0x0000;
    const SND_MEMORY: u32 = 0x0010;
    let spec = cue_spec(cue, tone);
    unsafe {
        // SYNCHRONOUS, from memory. Both flags are load-bearing and both were
        // found by measuring this machine rather than by reasoning; see the
        // PlaySoundW notes above for why SND_ASYNC and SND_ALIAS are unusable.
        let wav = cue_wav(&spec);
        let rc = PlaySoundW(wav.as_ptr(), core::ptr::null_mut(), SND_MEMORY | SND_SYNC);
        if rc != 0 {
            eprintln!("{cue}_chime: PlaySoundW refused the {tone} tone (rc={rc})");
            return Err(format!("PlaySoundW failed (rc={rc})"));
        }
        eprintln!("{cue}_chime: played {tone} ok");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn play_cue(_cue: &str, _tone: &str) -> Result<(), String> {
    Ok(())
}
'@ -split "`r?`n"

$lines.RemoveRange($start, $end - $start + 1)
$lines.InsertRange($start, [string[]]$new)
[IO.File]::WriteAllText($path, ($lines -join "`r`n"), $utf8)
Write-Host "done; new line count $($lines.Count)"