# Project Sentinel - Diagram Exporter (PowerShell)
# Exports all Mermaid diagrams to PNG and SVG formats

Write-Host "====================================" -ForegroundColor Cyan
Write-Host "Project Sentinel - Diagram Exporter" -ForegroundColor Cyan  
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

# Change to diagrams directory
$diagramsPath = ".\diagrams"
if (-not (Test-Path $diagramsPath)) {
    Write-Host "Error: diagrams directory not found!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Set-Location $diagramsPath

# Check for .mmd files
$mmdFiles = Get-ChildItem -Filter "*.mmd"
if ($mmdFiles.Count -eq 0) {
    Write-Host "Error: No .mmd files found in diagrams directory" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Found the following Mermaid files:" -ForegroundColor Green
$mmdFiles | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Yellow }
Write-Host ""

Write-Host "Starting diagram export..." -ForegroundColor Green
Write-Host ""

# Export each .mmd file
$successCount = 0
$totalCount = $mmdFiles.Count

foreach ($file in $mmdFiles) {
    $baseName = $file.BaseName
    $outputPng = "sentinel-$baseName.png"
    $outputSvg = "sentinel-$baseName.svg"
    
    Write-Host "Exporting $($file.Name)..." -ForegroundColor Cyan
    
    try {
        # Export to PNG (high resolution, white background)
        Write-Host "  - Creating $outputPng..." -ForegroundColor Gray
        $pngResult = & mmdc -i $file.FullName -o $outputPng -s 2 --backgroundColor white 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    ✓ PNG export successful" -ForegroundColor Green
        } else {
            Write-Host "    ✗ PNG export failed: $pngResult" -ForegroundColor Red
            continue
        }
        
        # Export to SVG (transparent background)
        Write-Host "  - Creating $outputSvg..." -ForegroundColor Gray
        $svgResult = & mmdc -i $file.FullName -o $outputSvg --backgroundColor transparent 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    ✓ SVG export successful" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host "    ✗ SVG export failed: $svgResult" -ForegroundColor Red
        }
        
    } catch {
        Write-Host "    ✗ Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
}

Write-Host ""
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "Export Summary" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

# List generated files
$pngFiles = Get-ChildItem -Filter "sentinel-*.png"
$svgFiles = Get-ChildItem -Filter "sentinel-*.svg"

Write-Host "Generated PNG files ($($pngFiles.Count)):" -ForegroundColor Green
$pngFiles | ForEach-Object { 
    $size = [math]::Round($_.Length / 1KB, 2)
    Write-Host "  - $($_.Name) ($size KB)" -ForegroundColor Yellow 
}
Write-Host ""

Write-Host "Generated SVG files ($($svgFiles.Count)):" -ForegroundColor Green
$svgFiles | ForEach-Object { 
    $size = [math]::Round($_.Length / 1KB, 2)
    Write-Host "  - $($_.Name) ($size KB)" -ForegroundColor Yellow 
}
Write-Host ""

Write-Host "====================================" -ForegroundColor Cyan
Write-Host "Export Complete!" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Successfully exported $successCount out of $totalCount diagrams" -ForegroundColor Green
Write-Host ""
Write-Host "Files saved in:" -ForegroundColor Cyan
Write-Host "  $((Get-Location).Path)" -ForegroundColor Yellow
Write-Host ""
Write-Host "You can now use these images in your documentation!" -ForegroundColor Green
Write-Host ""

# Open the diagrams folder
$openFolder = Read-Host "Would you like to open the diagrams folder? (y/N)"
if ($openFolder -eq "y" -or $openFolder -eq "Y") {
    Start-Process explorer.exe -ArgumentList (Get-Location).Path
}

Read-Host "Press Enter to exit"