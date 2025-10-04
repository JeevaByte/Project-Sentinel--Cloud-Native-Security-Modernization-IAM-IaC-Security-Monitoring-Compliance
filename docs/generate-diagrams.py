#!/usr/bin/env python3
"""
Project Sentinel - Mermaid Diagram Generator
This script extracts Mermaid diagrams from the markdown file and helps generate image files.
"""

import re
import os
import sys
import json
import base64
import requests
from urllib.parse import quote
import time

def extract_mermaid_blocks(markdown_file):
    """Extract all Mermaid code blocks from the markdown file."""
    with open(markdown_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all mermaid code blocks
    pattern = r'```mermaid\n(.*?)\n```'
    matches = re.findall(pattern, content, re.DOTALL)
    
    diagrams = []
    diagram_names = [
        "main-system-architecture",
        "security-architecture-flow", 
        "network-security-architecture",
        "devsecops-pipeline",
        "monitoring-observability",
        "compliance-governance",
        "threat-modeling-stride",
        "deployment-strategy"
    ]
    
    for i, match in enumerate(matches):
        name = diagram_names[i] if i < len(diagram_names) else f"diagram-{i+1}"
        diagrams.append({
            'name': name,
            'code': match.strip()
        })
    
    return diagrams

def generate_mermaid_url(mermaid_code):
    """Generate a Mermaid Live Editor URL for the diagram."""
    # Encode the mermaid code for URL
    encoded_code = quote(mermaid_code)
    base_url = "https://mermaid.live/edit"
    return f"{base_url}#{encoded_code}"

def save_diagram_urls(diagrams, output_dir):
    """Save URLs for each diagram to easily open in Mermaid Live Editor."""
    urls_file = os.path.join(output_dir, "mermaid-live-urls.md")
    
    with open(urls_file, 'w', encoding='utf-8') as f:
        f.write("# Project Sentinel - Mermaid Live Editor URLs\n\n")
        f.write("Click on each URL to open the diagram in Mermaid Live Editor for editing and export.\n\n")
        
        for i, diagram in enumerate(diagrams, 1):
            f.write(f"## {i}. {diagram['name'].replace('-', ' ').title()}\n\n")
            
            # Create a simple URL with the diagram name
            url = generate_mermaid_url(diagram['code'])
            f.write(f"**Mermaid Live Editor URL:**\n")
            f.write(f"[Open {diagram['name']} in Mermaid Live Editor]({url})\n\n")
            
            # Also save the raw code for easy copying
            f.write(f"**Raw Mermaid Code:**\n")
            f.write(f"```mermaid\n{diagram['code']}\n```\n\n")
            f.write("---\n\n")
    
    return urls_file

def create_diagram_files(diagrams, output_dir):
    """Create individual .mmd files for each diagram."""
    for diagram in diagrams:
        filename = f"{diagram['name']}.mmd"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(diagram['code'])
        
        print(f"Created: {filepath}")

def create_export_instructions(output_dir):
    """Create detailed instructions for exporting diagrams."""
    instructions_file = os.path.join(output_dir, "export-instructions.md")
    
    instructions = """# How to Export Diagrams from Mermaid Live Editor

## Quick Export Steps:

### Method 1: Using Mermaid Live Editor (Recommended)

1. **Open Mermaid Live Editor**: Visit https://mermaid.live/
2. **Copy & Paste**: Copy the Mermaid code from the .mmd files or from the URLs file
3. **Export Options**: Click the "Export" button and choose your format:
   - **PNG** - For documentation and presentations
   - **SVG** - For scalable graphics and web use
   - **PDF** - For high-quality documents

### Method 2: Using Mermaid CLI (Advanced)

Install Mermaid CLI:
```bash
npm install -g @mermaid-js/mermaid-cli
```

Generate PNG files:
```bash
mmdc -i main-system-architecture.mmd -o main-system-architecture.png
mmdc -i security-architecture-flow.mmd -o security-architecture-flow.png
mmdc -i network-security-architecture.mmd -o network-security-architecture.png
mmdc -i devsecops-pipeline.mmd -o devsecops-pipeline.png
mmdc -i monitoring-observability.mmd -o monitoring-observability.png
mmdc -i compliance-governance.mmd -o compliance-governance.png
mmdc -i threat-modeling-stride.mmd -o threat-modeling-stride.png
mmdc -i deployment-strategy.mmd -o deployment-strategy.png
```

Generate SVG files:
```bash
mmdc -i main-system-architecture.mmd -o main-system-architecture.svg
mmdc -i security-architecture-flow.mmd -o security-architecture-flow.svg
mmdc -i network-security-architecture.mmd -o network-security-architecture.svg
mmdc -i devsecops-pipeline.mmd -o devsecops-pipeline.svg
mmdc -i monitoring-observability.mmd -o monitoring-observability.svg
mmdc -i compliance-governance.mmd -o compliance-governance.svg
mmdc -i threat-modeling-stride.mmd -o threat-modeling-stride.svg
mmdc -i deployment-strategy.mmd -o deployment-strategy.svg
```

### Method 3: Batch Export Script

```bash
# Create a batch export script
for file in *.mmd; do
    name=$(basename "$file" .mmd)
    mmdc -i "$file" -o "${name}.png"
    mmdc -i "$file" -o "${name}.svg"
done
```

## Customization Options:

### Theme Configuration:
```bash
# Dark theme
mmdc -i diagram.mmd -o diagram.png -t dark

# Custom theme
mmdc -i diagram.mmd -o diagram.png -t base
```

### High-DPI Export:
```bash
# High resolution for presentations
mmdc -i diagram.mmd -o diagram.png -s 2
```

### Custom Dimensions:
```bash
# Specific width/height
mmdc -i diagram.mmd -o diagram.png -w 1920 -H 1080
```

## Recommended File Naming:

- `sentinel-main-architecture.png`
- `sentinel-security-flow.png`
- `sentinel-network-security.png`
- `sentinel-devsecops-pipeline.png`
- `sentinel-monitoring-observability.png`
- `sentinel-compliance-governance.png`
- `sentinel-threat-modeling.png`
- `sentinel-deployment-strategy.png`

## Integration with Documentation:

After exporting, you can embed the images in your documentation:

```markdown
![Project Sentinel Architecture](./docs/diagrams/sentinel-main-architecture.png)
```

Or in HTML:
```html
<img src="./docs/diagrams/sentinel-main-architecture.svg" alt="Project Sentinel Architecture" width="100%">
```
"""

    with open(instructions_file, 'w', encoding='utf-8') as f:
        f.write(instructions)
    
    return instructions_file

def main():
    """Main function to extract diagrams and create export files."""
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    markdown_file = os.path.join(script_dir, "architecture-diagrams-mermaid.md")
    
    # Create diagrams subdirectory
    diagrams_dir = os.path.join(script_dir, "diagrams")
    os.makedirs(diagrams_dir, exist_ok=True)
    
    print("🎯 Project Sentinel - Mermaid Diagram Generator")
    print("=" * 50)
    
    # Extract diagrams from markdown
    print(f"📖 Reading diagrams from: {markdown_file}")
    diagrams = extract_mermaid_blocks(markdown_file)
    print(f"✅ Found {len(diagrams)} diagrams")
    
    # Create individual .mmd files
    print(f"📁 Creating .mmd files in: {diagrams_dir}")
    create_diagram_files(diagrams, diagrams_dir)
    
    # Create URLs file for Mermaid Live Editor
    print("🔗 Creating Mermaid Live Editor URLs...")
    urls_file = save_diagram_urls(diagrams, diagrams_dir)
    print(f"✅ Created: {urls_file}")
    
    # Create export instructions
    print("📋 Creating export instructions...")
    instructions_file = create_export_instructions(diagrams_dir)
    print(f"✅ Created: {instructions_file}")
    
    print("\n🎉 All files created successfully!")
    print("\n📋 Next Steps:")
    print(f"1. Open: {urls_file}")
    print("2. Click on the Mermaid Live Editor URLs to view/edit diagrams")
    print("3. Export diagrams as PNG/SVG from the live editor")
    print(f"4. Follow instructions in: {instructions_file}")
    print(f"5. Save exported images to: {diagrams_dir}")
    
    # List all created files
    print(f"\n📁 Created Files in {diagrams_dir}:")
    for file in os.listdir(diagrams_dir):
        print(f"   - {file}")

if __name__ == "__main__":
    main()