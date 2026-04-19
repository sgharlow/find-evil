#Requires -Version 5.1
# Record the live Claude Code + find-evil MCP investigation.
#
# Layout on screen during recording:
#   - Foreground (big, maximized): live-demo-display.py - shows tool calls
#     streaming in from output/audit_trail.jsonl, and the IR report + STIX
#     bundle at the end. This is what the camera focuses on.
#   - Background (minimized): claude -p running the investigation. Silent
#     from the user's perspective; the MCP tools write to output/ as it works.
#
# ffmpeg captures the primary monitor at 30 fps for up to 12 minutes or
# until the display script exits, whichever comes first.
#
# Output: screenshots/live-investigation.mp4

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

# Fresh output state
Remove-Item -Force -ErrorAction SilentlyContinue `
    "$repoRoot\output\audit_trail.jsonl", `
    "$repoRoot\output\findings.db", `
    "$repoRoot\output\bundle.stix.json", `
    "$repoRoot\output\ir_report.md"

$screenshotDir = Join-Path $repoRoot 'screenshots'
if (-not (Test-Path $screenshotDir)) { New-Item -ItemType Directory -Force -Path $screenshotDir | Out-Null }
$videoPath = Join-Path $screenshotDir 'live-investigation.mp4'
Remove-Item -Force -ErrorAction SilentlyContinue $videoPath

# Load Win32 helpers for window management
Add-Type -Namespace Win32Helper -Name Native -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
[DllImport("user32.dll")]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@

# The investigation prompt - matches demo/live_investigation.md guidance
$prompt = @'
You have access to the find-evil MCP server with 15 read-only forensic tools. Investigate the evidence directory /evidence using whatever tools apply.

The evidence contains: a Windows Application event log (Application_small.evtx), SYSTEM and SOFTWARE registry hives, a binary file with embedded indicators (evidence_iocs.bin), and a YARA rules file (find_evil_rules.yar). Memory forensics tools (vol_*) will fail because there is no .raw memory image present - that is expected; skip them.

Follow this protocol:
1. Call session_init with evidence_dir="/evidence" to seal all files.
2. Call list_sealed_evidence to see the manifest.
3. Call parse_evtx on /evidence/Application_small.evtx to extract Windows events.
4. Call registry_query on /evidence/SYSTEM and /evidence/SOFTWARE to find persistence keys, services.
5. Call yara_scan on /evidence with the rules file /evidence/find_evil_rules.yar to find IOC patterns.
6. Submit findings using submit_finding with evidence_strength and corroboration scores. Reference the invocation_id from each tool's response.
7. Call generate_report with title="Live Investigation Report" to produce the markdown IR report.
8. Call export_stix to produce the STIX 2.1 bundle.

Be concise in your reasoning between tool calls. The goal is to exercise the tool surface with real evidence and produce the final report + STIX bundle.
'@

$promptPath = Join-Path $env:TEMP "find-evil-prompt-$([guid]::NewGuid()).txt"
Set-Content -Path $promptPath -Value $prompt -Encoding UTF8

# --- Launch the background claude session ----------------------------
# Runs claude -p with the prompt piped on stdin; stdout/stderr go to a log file.
$claudeLog = Join-Path $env:TEMP "claude-live-$([guid]::NewGuid()).log"
$claudeProc = Start-Process -FilePath 'powershell.exe' `
    -ArgumentList @(
        '-NoProfile','-WindowStyle','Minimized',
        '-Command',
        "Set-Location '$repoRoot'; Get-Content '$promptPath' -Raw | claude -p --permission-mode bypassPermissions | Tee-Object -FilePath '$claudeLog'; Start-Sleep -Seconds 5"
    ) `
    -WindowStyle Minimized `
    -PassThru

Write-Host "Claude background PID: $($claudeProc.Id) (minimized)"
Write-Host "Claude stdout log:     $claudeLog"

# --- Launch the foreground display window (maximized) ----------------
$displayTitle = 'FIND-EVIL-LIVE-INVESTIGATION'
$displayProc = Start-Process -FilePath 'powershell.exe' `
    -ArgumentList @(
        '-NoExit','-Command',
        "`$Host.UI.RawUI.WindowTitle = '$displayTitle'; Set-Location '$repoRoot'; `$env:PYTHONIOENCODING='utf-8'; python scripts\live-demo-display.py"
    ) `
    -WindowStyle Maximized `
    -PassThru

Write-Host "Display foreground PID: $($displayProc.Id) (maximized)"

# Give windows time to create
Start-Sleep -Milliseconds 4000

# Bring display to foreground + maximize
$hwnd = [Win32Helper.Native]::FindWindow($null, $displayTitle)
if ($hwnd -ne [IntPtr]::Zero) {
    [Win32Helper.Native]::ShowWindow($hwnd, 3) | Out-Null   # SW_MAXIMIZE
    [Win32Helper.Native]::SetForegroundWindow($hwnd) | Out-Null
    Write-Host "Brought display window to foreground (HWND $hwnd)"
} else {
    Write-Warning "Couldn't locate display window by title"
}

# --- Start ffmpeg recording (up to 12 min; stops early if claude finishes) --
$duration = 720  # 12 min cap
Write-Host "Starting ffmpeg capture (up to ${duration}s) -> $videoPath"

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

$ffmpegProc = Start-Process -FilePath 'ffmpeg' -ArgumentList $ffmpegArgs `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardError (Join-Path $env:TEMP 'ffmpeg-live.err') `
    -RedirectStandardOutput (Join-Path $env:TEMP 'ffmpeg-live.out')

Write-Host "ffmpeg PID: $($ffmpegProc.Id)"

# --- Wait for either claude to finish OR display script to exit ------
Write-Host ""
Write-Host "Recording. Claude is analyzing in the background. Leave the desktop alone."
Write-Host "Will stop when the display script signals completion (idle + report present)."
Write-Host ""

$start = Get-Date
while ($true) {
    Start-Sleep -Seconds 2
    $elapsed = [int]((Get-Date) - $start).TotalSeconds

    # Done when display script exits (it waits for ir_report.md + 15s idle)
    if ($displayProc.HasExited) {
        Write-Host "[${elapsed}s] display script exited - stopping recording"
        break
    }
    # Hard cap at duration
    if ($elapsed -ge $duration - 5) {
        Write-Host "[${elapsed}s] hit duration cap - stopping recording"
        break
    }
    # Claude finished but display may still be showing artifacts - give it 20s
    if ($claudeProc.HasExited -and $elapsed -gt 30) {
        # If claude has been gone 20 s and display is still running, force stop
        $claudeIdle = [int]((Get-Date) - $claudeProc.ExitTime).TotalSeconds
        if ($claudeIdle -gt 20) {
            Write-Host "[${elapsed}s] claude exited ${claudeIdle}s ago - stopping"
            break
        }
    }
    if ($elapsed % 30 -eq 0) {
        $auditLines = if (Test-Path "$repoRoot\output\audit_trail.jsonl") { (Get-Content "$repoRoot\output\audit_trail.jsonl" | Measure-Object -Line).Lines } else { 0 }
        Write-Host "[${elapsed}s] claude running=$(-not $claudeProc.HasExited)  audit lines=$auditLines"
    }
}

# Pause for cinematic breath, then let user see final report for ~5s
Start-Sleep -Seconds 5

# --- Stop ffmpeg (SIGINT equivalent via finalize quit) ----------------
Write-Host "Stopping ffmpeg (PID $($ffmpegProc.Id))"
try {
    # ffmpeg responds to 'q' on stdin; without that, Stop-Process with force leaves the MP4 unfinalized.
    # Best approach on Windows: send WM_CLOSE via taskkill (not /F).
    & taskkill /PID $ffmpegProc.Id 2>&1 | Out-Null
    # Give ffmpeg ~5 s to flush and finalize
    $ffmpegProc.WaitForExit(10000) | Out-Null
} catch {}

# If it's still running, force it
if (-not $ffmpegProc.HasExited) {
    Stop-Process -Id $ffmpegProc.Id -Force -ErrorAction SilentlyContinue
}

Start-Sleep -Milliseconds 500

# --- Clean up the two helper windows ----------------------------------
try { if (-not $claudeProc.HasExited)  { Stop-Process -Id $claudeProc.Id  -Force -ErrorAction SilentlyContinue } } catch {}
try { if (-not $displayProc.HasExited) { Stop-Process -Id $displayProc.Id -Force -ErrorAction SilentlyContinue } } catch {}

Remove-Item -Force -ErrorAction SilentlyContinue $promptPath

# --- Report -----------------------------------------------------------
$auditPath  = Join-Path $repoRoot 'output\audit_trail.jsonl'
$reportPath = Join-Path $repoRoot 'output\ir_report.md'
$stixPath   = Join-Path $repoRoot 'output\bundle.stix.json'

$auditLines = 0
if (Test-Path $auditPath) {
    $auditLines = (Get-Content $auditPath | Measure-Object -Line).Lines
}
$reportExists = Test-Path $reportPath
$stixExists   = Test-Path $stixPath

Write-Host ""
Write-Host "=== DONE ==="
if (Test-Path $videoPath) {
    $size = (Get-Item $videoPath).Length
    Write-Host ("Video:     {0}  ({1:N2} MB)" -f $videoPath, ($size / 1MB))
} else {
    Write-Host "Video:     NOT FOUND - ffmpeg may have failed. Check $env:TEMP\ffmpeg-live.err"
}
Write-Host "IR report: $reportPath  (exists: $reportExists)"
Write-Host "STIX:      $stixPath  (exists: $stixExists)"
Write-Host "Audit:     $auditPath  (lines: $auditLines)"
