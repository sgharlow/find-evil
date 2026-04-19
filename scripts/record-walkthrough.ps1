#Requires -Version 5.1
# Orchestrate find-evil walkthrough video recording
# - Launches validate_submission.py + video_demo.py in a visible pwsh window
# - Brings that window to foreground
# - Records primary monitor with ffmpeg for 90s
# - Saves screenshots/walkthrough.mp4

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

Remove-Item -Force -ErrorAction SilentlyContinue "$repoRoot\output\audit_trail.jsonl", "$repoRoot\output\findings.db", "$repoRoot\output\bundle.stix.json"

$screenshotDir = Join-Path $repoRoot 'screenshots'
if (-not (Test-Path $screenshotDir)) { New-Item -ItemType Directory -Force -Path $screenshotDir | Out-Null }
$videoPath = Join-Path $screenshotDir 'walkthrough.mp4'
Remove-Item -Force -ErrorAction SilentlyContinue $videoPath

$demoTitle = 'FIND-EVIL-DEMO-WALKTHROUGH'
$demoRunnerPath = Join-Path $PSScriptRoot 'demo-runner.ps1'

# Launch the demo window first, wait for it to appear
$demoProc = Start-Process -FilePath 'powershell.exe' `
    -ArgumentList @('-NoExit','-ExecutionPolicy','Bypass','-File',$demoRunnerPath,'-RepoRoot',$repoRoot,'-WindowTitle',$demoTitle) `
    -WindowStyle Normal -PassThru

Write-Host "Demo launched in pwsh PID $($demoProc.Id), title '$demoTitle'"

Add-Type -Namespace Win32Helper -Name Native -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@

Start-Sleep -Milliseconds 3500

$hwnd = [Win32Helper.Native]::FindWindow($null, $demoTitle)
if ($hwnd -ne [IntPtr]::Zero) {
    [Win32Helper.Native]::ShowWindow($hwnd, 3) | Out-Null   # SW_MAXIMIZE
    [Win32Helper.Native]::SetForegroundWindow($hwnd) | Out-Null
    Write-Host "Brought demo window to foreground + maximized (HWND $hwnd)"
}
else {
    Write-Warning "Could not locate demo window by title - recording proceeds anyway"
}

# ffmpeg: capture primary desktop for 90s at 30fps, H.264 CRF 23, yuv420p for player compat
$duration = 90
Write-Host "Starting ffmpeg capture for ${duration}s -> $videoPath"
$ffmpegArgs = @(
    '-y',
    '-f', 'gdigrab',
    '-framerate', '30',
    '-i', 'desktop',
    '-t', $duration,
    '-c:v', 'libx264',
    '-crf', '23',
    '-preset', 'fast',
    '-pix_fmt', 'yuv420p',
    $videoPath
)

# Run ffmpeg synchronously; it blocks until duration elapses
& ffmpeg @ffmpegArgs 2>&1 | Select-Object -Last 8

Write-Host "ffmpeg complete"
if (Test-Path $videoPath) {
    $size = (Get-Item $videoPath).Length
    Write-Host ("Output: {0} ({1} KB)" -f $videoPath, [int]($size / 1024))
}

# Clean up demo window if still running
if (-not $demoProc.HasExited) {
    Write-Host "Closing demo pwsh PID $($demoProc.Id)"
    try { Stop-Process -Id $demoProc.Id -Force -ErrorAction SilentlyContinue } catch {}
}
