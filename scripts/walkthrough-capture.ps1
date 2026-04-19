#Requires -Version 5.1
# Orchestrates find-evil walkthrough capture
# - Launches validate_submission.py then video_demo.py in a new visible pwsh window
# - Captures primary monitor every 10s for 80s to ./screenshots/

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

Remove-Item -Force -ErrorAction SilentlyContinue "$repoRoot\output\audit_trail.jsonl", "$repoRoot\output\findings.db", "$repoRoot\output\bundle.stix.json"

$screenshotDir = Join-Path $repoRoot 'screenshots'
if (-not (Test-Path $screenshotDir)) { New-Item -ItemType Directory -Force -Path $screenshotDir | Out-Null }

$demoTitle = 'FIND-EVIL-DEMO-WALKTHROUGH'
$demoRunnerPath = Join-Path $PSScriptRoot 'demo-runner.ps1'

$demoProc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoExit','-ExecutionPolicy','Bypass','-File',$demoRunnerPath,'-RepoRoot',$repoRoot,'-WindowTitle',$demoTitle) -WindowStyle Normal -PassThru

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

Start-Sleep -Milliseconds 4500

$hwnd = [Win32Helper.Native]::FindWindow($null, $demoTitle)
if ($hwnd -ne [IntPtr]::Zero) {
    [Win32Helper.Native]::ShowWindow($hwnd, 9) | Out-Null
    [Win32Helper.Native]::SetForegroundWindow($hwnd) | Out-Null
    Write-Host "Brought demo window to foreground (HWND $hwnd)"
}
else {
    Write-Warning "Could not locate demo window by title - capture proceeds anyway"
}

& "$PSScriptRoot\capture-demo-screenshots.ps1" -TotalSeconds 80 -IntervalSeconds 10 -OutDir $screenshotDir

Write-Host "Capture complete. Demo pwsh PID $($demoProc.Id) - close it manually if still open."
