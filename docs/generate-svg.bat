@echo off
echo Generating SVG versions of all diagrams...
echo.

cd diagrams

for %%f in (*.mmd) do (
    echo Converting %%f to SVG...
    mmdc -i "%%f" -o "sentinel-%%~nf.svg" --backgroundColor transparent
)

echo.
echo SVG generation complete!
echo.
echo Listing all generated files:
dir sentinel-*.*
pause