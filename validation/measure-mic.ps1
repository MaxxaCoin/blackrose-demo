# Measure the real capture level from the DEFAULT input device for 3s.
// This is the ground truth for "will the mic hear anything": the
// Settings "Test your microphone" meter and this agree, but this also
// reports the peak dBFS/amplitude so a silent-but-present device is
// distinguishable from a working one.
// Run: powershell -File measure-mic.ps1
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Speech
Write-Output ('recognizers: ' + ([System.Speech.Recognition.SpeechRecognitionEngine]::InstalledRecognizers() | ForEach-Object { $_.Culture.Name }) -join ', ')

# Raw capture via the WinMM waveIn API, so we see the signal even when no
# recognizer is loaded.
$code = @'
using System;
using System.Runtime.InteropServices;
public class Wave {
  [DllImport("winmm.dll")] public static extern uint waveInOpen(out IntPtr h, uint dev, int fmt, int cb, int c, uint flags);
  [DllImport("winmm.dll")] public static extern uint waveInStart(IntPtr h);
  [DllImport("winmm.dll")] public static extern uint waveInStop(IntPtr h);
  [DllImport("winmm.dll")] public static extern uint waveInClose(IntPtr h);
  [DllImport("winmm.dll")] public static extern uint waveInReset(IntPtr h);
  [DllImport("winmm.dll", CharSet=CharSet.Auto)] public static extern uint waveInGetDevCaps(IntPtr h, ref Caps c, uint size);
  [DllImport("winmm.dll")] public static extern uint waveInPrepareHeader(IntPtr h, IntPtr hdr, uint size);
  [DllImport("winmm.dll")] public static extern uint waveInUnprepareHeader(IntPtr h, IntPtr hdr, uint size);
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]
  public struct Caps { public uint wMid, wPid; [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string szPname; public uint dwFormats; public ushort wChannels; public ushort wReserved1; }
}
'@
Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue

$h = [IntPtr]::Zero
# WAVEFORMAT: wFormatTag(16) | nChannels(16) | nSamplesPerSec(32) |
# nAvgBytesPerSec(32) | nBlockAlign(16) | wBitsPerSample(16)
# 8000 Hz, 8-bit, mono => 8000 | (1 << 22) | (1 << 16)
$fmt = [int](8000 -bor (1 -shl 22) -bor (1 -shl 16))
$WAVE_MAPPER = [uint32]0xFFFFFFFF
$rc = [Wave]::waveInOpen([ref]$h, $WAVE_MAPPER, $fmt, 0, 0, 0)
if ($rc -ne 0) { Write-Output ("waveInOpen failed: " + $rc + " (no usable capture device)"); exit 1 }

$caps = New-Object Wave+Caps
[void][Wave]::waveInGetDevCaps($h, [ref]$caps, [Runtime.InteropServices.Marshal]::SizeOf($caps))
Write-Output ('device name: ' + $caps.szPname + '  (channels=' + $caps.wChannels + ')')

$bufSize = 8000 * 3
$hdr = [Runtime.InteropServices.Marshal]::AllocHGlobal(48)
[void][Wave]::waveInPrepareHeader($h, $hdr, 48)
[void][Wave]::waveInReset($h)
$sz = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
[Runtime.InteropServices.Marshal]::WriteInt32($sz, 0)
$WHDR_DONE = 0x00000001
$peak = 0
$done = 0
[void][Wave]::waveInStart($h)
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Milliseconds 100
  $flags = [Runtime.InteropServices.Marshal]::ReadInt32($hdr, 8)  # dwFlags
  if ($flags -band $WHDR_DONE) {
    $len = [Runtime.InteropServices.Marshal]::ReadInt32($hdr, 12) # dwBytesRecorded
    $data = [byte[]]::new($len)
    # lpData sits at offset 24 in the WAVEHDR struct
    [Runtime.InteropServices.Marshal]::Copy($hdr.ToInt64() + 24, $data, 0, $len)
    foreach ($b in $data) { $a = [Math]::Abs([int]$b - 128); if ($a -gt $peak) { $peak = $a } }
    $done++
    [void][Wave]::waveInUnprepareHeader($h, $hdr, 48)
    [void][Wave]::waveInPrepareHeader($h, $hdr, 48)
    [void][Wave]::waveInReset($h)
    [void][Wave]::waveInStart($h)
  }
}
[void][Wave]::waveInStop($h)
[void][Wave]::waveInUnprepareHeader($h, $hdr, 48)
[void][Wave]::waveInClose($h)
[Runtime.InteropServices.Marshal]::FreeHGlobal($hdr)
[Runtime.InteropServices.Marshal]::FreeHGlobal($sz)

Write-Output ('buffers captured: ' + $done)
Write-Output ('peak amplitude (0-128, 8-bit): ' + $peak)
if ($peak -le 2) { Write-Output 'VERDICT: SILENT - the device is open but nothing is reaching it.' }
elseif ($peak -lt 12) { Write-Output 'VERDICT: VERY QUIET - check mic gain/boost, may be too low for dictation.' }
else { Write-Output 'VERDICT: HEALTHY - real signal present.' }
