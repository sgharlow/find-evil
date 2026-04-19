param(
    [int]$TotalSeconds = 80,
    [int]$IntervalSeconds = 10,
    [string]$OutDir = ".\screenshots"
)

# Capture primary monitor screenshots every $IntervalSeconds for $TotalSeconds.
# Writes PNG files into $OutDir with zero-padded index + timestamp.
# Intended to run concurrently with the demo in a visible terminal window.

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$frames = [math]::Floor($TotalSeconds / $IntervalSeconds)

Write-Host ("Capturing {0} frames every {1}s to {2} ({3}x{4})" -f $frames, $IntervalSeconds, $OutDir, $bounds.Width, $bounds.Height)

for ($i = 1; $i -le $frames; $i++) {
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)

    $idx = '{0:D2}' -f $i
    $ts = Get-Date -Format 'HHmmss'
    $path = Join-Path $OutDir "frame_${idx}_$ts.png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Host "  [$idx/$frames] $path"

    if ($i -lt $frames) { Start-Sleep -Seconds $IntervalSeconds }
}

Write-Host "Done - $frames frames written."
