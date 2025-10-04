@echo off
echo ====================================
echo Project Sentinel - Diagram Exporter
echo ====================================
echo.

REM Change to the diagrams directory
cd diagrams
if not exist "*.mmd" (
    echo Error: No .mmd files found in diagrams directory
    pause
    exit /b 1
)

echo Found the following Mermaid files:
dir *.mmd /b
echo.

echo Starting diagram export...
echo.

REM Export each .mmd file to PNG and SVG
for %%f in (*.mmd) do (
    echo Exporting %%f...
    
    REM Get filename without extension
    set "filename=%%~nf"
    
    REM Export to PNG (high resolution)
    echo   - Creating sentinel-%%~nf.png...
    mmdc -i "%%f" -o "sentinel-%%~nf.png" -s 2 --backgroundColor white
    
    REM Export to SVG
    echo   - Creating sentinel-%%~nf.svg...
    mmdc -i "%%f" -o "sentinel-%%~nf.svg" --backgroundColor transparent
    
    echo   ✓ Completed %%f
    echo.
)

echo.
echo ====================================
echo Export Summary
echo ====================================
echo.
echo Generated PNG files:
dir sentinel-*.png /b 2>nul
echo.
echo Generated SVG files:
dir sentinel-*.svg /b 2>nul
echo.

echo ====================================
echo Export Complete!
echo ====================================
echo.
echo All diagrams have been exported to:
echo   - PNG files (high resolution, white background)
echo   - SVG files (scalable, transparent background)
echo.
echo You can now use these images in your documentation!
echo.
pause