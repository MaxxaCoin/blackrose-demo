# Capture the BlackRose window to a PNG so we can see what the user sees
# instead of guessing from process state. Usage:
#   powershell -ExecutionPolicy Bypass -File screenshot-blackrose.ps1 [OutPng]
param([string]$OutPng = 'C:\Users\pc\Desktop\BlackRose\validation\blackrose-window.png', [string]$Proc = 'BlackRose')
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$p = Get-Process $Proc -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $p) { Write-Output ("no visible " + $Proc + " window"); exit 1 }
$h = $p.MainWindowHandle
# GetWindowRect via P/Invoke (MainWindowHandle alone does not give the size)
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Win {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
}
'@
Write-Output ('visible: ' + [Win]::IsWindowVisible($h))
# Bring it to the front first: CopyFromScreen captures whatever is ON SCREEN at
# those coordinates, so a browser window overlapping the app would be captured
# instead of the app (this is how we nearly misdiagnosed a browser tab as the
# desktop shell on 2026-09-28).
[void][Win]::ShowWindow($h, 9)   # SW_RESTORE
[void][Win]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 900
$rect = New-Object Win+RECT
[void][Win]::GetWindowRect($h, [ref]$rect)
$w = $rect.R - $rect.L; $ht = $rect.B - $rect.T
Write-Output ("window: " + $w + "x" + $ht + " at " + $rect.L + "," + $rect.T)
if ($w -le 0 -or $ht -le 0) { Write-Output 'window has no area (minimised?)'; exit 1 }
$bmp = New-Object System.Drawing.Bitmap $w, $ht
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($rect.L, $rect.T, 0, 0, (New-Object System.Drawing.Size $w, $ht))
$bmp.Save($OutPng, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output ('saved ' + $OutPng)
