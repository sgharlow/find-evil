param(
    [string]$RepoRoot,
    [string]$WindowTitle
)

$Host.UI.RawUI.WindowTitle = $WindowTitle
Set-Location $RepoRoot
$env:PYTHONIOENCODING = 'utf-8'

Write-Host '=== Phase 1: validate_submission.py ==='
python demo/validate_submission.py

Write-Host ''
Write-Host '=== Phase 2: video_demo.py ==='
python demo/video_demo.py

Write-Host ''
Write-Host '=== walkthrough complete ==='
Start-Sleep -Seconds 15
