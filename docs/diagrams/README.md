# Project Sentinel - Architecture Diagrams

This folder contains all Project Sentinel architecture diagrams organized by file type for easy access and management.

## 📁 Folder Structure

```
diagrams/
├── 📖 documentation/          # Documentation and guides
│   ├── diagram-summary.md     # Complete overview of all diagrams
│   ├── export-instructions.md # Detailed export guide
│   └── mermaid-live-urls.md   # Direct Mermaid Live Editor links
│
├── 🖼️ png/                    # High-resolution PNG files
│   ├── sentinel-compliance-governance.png
│   ├── sentinel-deployment-strategy.png
│   ├── sentinel-devsecops-pipeline.png
│   ├── sentinel-main-system-architecture.png
│   ├── sentinel-monitoring-observability.png
│   ├── sentinel-network-security-architecture.png
│   ├── sentinel-security-architecture-flow.png
│   └── sentinel-threat-modeling-stride.png
│
├── 🎨 svg/                    # Scalable vector graphics
│   ├── sentinel-compliance-governance.svg
│   ├── sentinel-deployment-strategy.svg
│   ├── sentinel-devsecops-pipeline.svg
│   ├── sentinel-main-system-architecture.svg
│   ├── sentinel-monitoring-observability.svg
│   ├── sentinel-network-security-architecture.svg
│   ├── sentinel-security-architecture-flow.svg
│   └── sentinel-threat-modeling-stride.svg
│
└── 💻 source/                 # Mermaid source files
    ├── compliance-governance.mmd
    ├── deployment-strategy.mmd
    ├── devsecops-pipeline.mmd
    ├── main-system-architecture.mmd
    ├── monitoring-observability.mmd
    ├── network-security-architecture.mmd
    ├── security-architecture-flow.mmd
    └── threat-modeling-stride.mmd
```

## 🎯 Quick Access Guide

### 📖 **For Documentation Writers:**
- **Use PNG files** from `/png/` folder for README files and documentation
- **Use SVG files** from `/svg/` folder for responsive web content
- **Reference paths**: `./docs/diagrams/png/filename.png` or `./docs/diagrams/svg/filename.svg`

### 🎨 **For Presentation Creators:**
- **Use PNG files** from `/png/` folder for PowerPoint and presentations
- High-resolution (2x scale) for crisp display
- White background integrates well with slides

### 💻 **For Developers & Editors:**
- **Edit source files** in `/source/` folder (`.mmd` files)
- **Regenerate exports** using Mermaid CLI or Live Editor
- **Documentation** in `/documentation/` for export guidance

### 🌐 **For Web Developers:**
- **Use SVG files** from `/svg/` folder for websites
- Transparent background adapts to any theme
- Scalable for responsive design

## 📊 Diagram Inventory

### 1. **Main System Architecture** 
- **File**: `sentinel-main-system-architecture.*`
- **Purpose**: Complete Project Sentinel platform overview
- **Components**: Kubernetes, security tools, monitoring stack
- **Best for**: Executive presentations, technical overviews

### 2. **Security Architecture Flow**
- **File**: `sentinel-security-architecture-flow.*`
- **Purpose**: Security component interactions and data flows
- **Focus**: Threat detection, policy enforcement, compliance
- **Best for**: Security team briefings, compliance reviews

### 3. **Network Security Architecture**
- **File**: `sentinel-network-security-architecture.*`
- **Purpose**: Network segmentation and security controls
- **Focus**: DMZ zones, internal networks, traffic flow
- **Best for**: Network architecture reviews, security audits

### 4. **DevSecOps Pipeline**
- **File**: `sentinel-devsecops-pipeline.*`
- **Purpose**: Security-integrated CI/CD workflow
- **Focus**: Security gates, automated scanning, deployment
- **Best for**: DevOps team training, process documentation

### 5. **Monitoring & Observability**
- **File**: `sentinel-monitoring-observability.*`
- **Purpose**: Comprehensive monitoring architecture
- **Focus**: Metrics, logs, traces, alerting systems
- **Best for**: SRE documentation, monitoring setup

### 6. **Compliance & Governance**
- **File**: `sentinel-compliance-governance.*`
- **Purpose**: Regulatory compliance framework
- **Focus**: CIS, NIST, ISO 27001, automated compliance
- **Best for**: Compliance reports, audit documentation

### 7. **Threat Modeling (STRIDE)**
- **File**: `sentinel-threat-modeling-stride.*`
- **Purpose**: Threat analysis and security mitigations
- **Focus**: STRIDE methodology, attack vectors, controls
- **Best for**: Security assessments, threat analysis

### 8. **Deployment Strategy**
- **File**: `sentinel-deployment-strategy.*`
- **Purpose**: Multi-environment deployment workflow
- **Focus**: Development, staging, production pipelines
- **Best for**: Release planning, environment documentation

## 🚀 Usage Examples

### Markdown Documentation:
```markdown
# Project Sentinel Architecture
![Main Architecture](./docs/diagrams/png/sentinel-main-system-architecture.png)

## Security Components
![Security Flow](./docs/diagrams/svg/sentinel-security-architecture-flow.svg)
```

### HTML/Web:
```html
<!-- Responsive SVG -->
<img src="./docs/diagrams/svg/sentinel-main-system-architecture.svg" 
     alt="Project Sentinel Architecture" 
     style="width: 100%; max-width: 1200px;">

<!-- Fixed PNG -->
<img src="./docs/diagrams/png/sentinel-security-architecture-flow.png" 
     alt="Security Flow" 
     width="800">
```

### PowerPoint/Presentations:
1. Navigate to `/png/` folder
2. Insert → Pictures → select desired diagram
3. Resize as needed (maintains quality due to 2x scaling)

## 🔄 Updating Diagrams

### To Edit and Re-export:
1. **Edit source**: Modify files in `/source/` folder
2. **Export PNG**: `mmdc -i source/diagram.mmd -o png/sentinel-diagram.png -s 2 --backgroundColor white`
3. **Export SVG**: `mmdc -i source/diagram.mmd -o svg/sentinel-diagram.svg --backgroundColor transparent`
4. **Documentation**: Update `/documentation/` files if structure changes

### Quick Commands:
```bash
# Navigate to diagrams folder
cd docs/diagrams

# Export single diagram to both formats
mmdc -i source/main-system-architecture.mmd -o png/sentinel-main-system-architecture.png -s 2 --backgroundColor white
mmdc -i source/main-system-architecture.mmd -o svg/sentinel-main-system-architecture.svg --backgroundColor transparent

# Batch export all (Windows)
# See documentation/export-instructions.md for batch scripts
```

## 📋 File Specifications

### PNG Files:
- **Resolution**: High DPI (2x scale)
- **Background**: White
- **Format**: PNG-24 with full color
- **Usage**: Presentations, documentation, print

### SVG Files:
- **Format**: Scalable Vector Graphics
- **Background**: Transparent
- **Compatibility**: All modern browsers
- **Usage**: Web, responsive design, high-quality scaling

### Source Files (.mmd):
- **Format**: Mermaid diagram syntax
- **Editability**: Text-based, version control friendly
- **Tools**: Mermaid Live Editor, VS Code extensions
- **Purpose**: Source of truth for all diagrams

## 🔗 Related Files

- **Parent Directory**: `../export-diagrams.bat` - Windows export script
- **Parent Directory**: `../export-diagrams.ps1` - PowerShell export script  
- **Parent Directory**: `../generate-svg.bat` - SVG-only export script
- **Documentation**: `documentation/` folder contains detailed guides

## 📞 Support

For questions about diagram usage or editing:
1. Check `documentation/export-instructions.md` for detailed guidance
2. Use `documentation/mermaid-live-urls.md` for quick online editing
3. Review `documentation/diagram-summary.md` for complete overview

---

**Project Sentinel Architecture Diagrams**  
Organized: October 4, 2025  
Total Files: 27 (8 source + 8 PNG + 8 SVG + 3 documentation)  
Structure: Organized by file type for optimal workflow