# Project Sentinel - Architecture Diagram Prompts for Eraser

This document provides detailed prompts for creating comprehensive architecture diagrams using Eraser, a Kubernetes-native diagramming tool that can generate diagrams from YAML configurations.

## 🎨 Eraser Overview

Eraser is a tool that creates architecture diagrams as code, allowing you to:
- Generate consistent, version-controlled diagrams
- Automatically update diagrams when infrastructure changes
- Create multiple views (logical, physical, security, network)
- Export to various formats (PNG, SVG, PDF)

## 🏗️ Main Architecture Diagram Prompt

### Prompt for Complete System Architecture

```yaml
# Project Sentinel - Complete System Architecture
# Use this prompt with Eraser to generate the main architecture diagram

apiVersion: eraserdiagram.io/v1alpha1
kind: Diagram
metadata:
  name: sentinel-main-architecture
  namespace: default
spec:
  title: "Project Sentinel - Enterprise Security Platform"
  description: "Comprehensive cloud-native security platform with multi-layered protection"
  
  # Define the layout and styling
  layout:
    direction: TB  # Top to Bottom
    spacing: 50
    
  # Define node styles
  styles:
    - name: kubernetes-cluster
      fillColor: "#326CE5"
      textColor: "white"
      borderColor: "#1E3A8A"
      borderWidth: 2
      
    - name: security-component
      fillColor: "#DC2626"
      textColor: "white"
      borderColor: "#991B1B"
      borderWidth: 2
      
    - name: monitoring-component
      fillColor: "#059669"
      textColor: "white"
      borderColor: "#047857"
      borderWidth: 2
      
    - name: application
      fillColor: "#7C3AED"
      textColor: "white"
      borderColor: "#5B21B6"
      borderWidth: 2
      
    - name: external-service
      fillColor: "#F59E0B"
      textColor: "white"
      borderColor: "#D97706"
      borderWidth: 2

  # Define the nodes and their relationships
  nodes:
    # Developer/User Entry Points
    - id: developer
      label: "Security Team\n& Developers"
      style: external-service
      
    - id: cicd
      label: "CI/CD Pipeline\nGitHub Actions"
      style: external-service
      
    # Kubernetes Cluster
    - id: k8s-cluster
      label: "Kubernetes Cluster\n(kind/EKS/AKS/GKE)"
      style: kubernetes-cluster
      
    # Namespaces within cluster
    - id: ns-apps
      label: "sentinel-apps\nNamespace"
      style: kubernetes-cluster
      parent: k8s-cluster
      
    - id: ns-security
      label: "sentinel-security\nNamespace"
      style: kubernetes-cluster
      parent: k8s-cluster
      
    - id: ns-monitoring
      label: "monitoring\nNamespace"
      style: kubernetes-cluster
      parent: k8s-cluster
      
    - id: ns-vault
      label: "vault\nNamespace"
      style: kubernetes-cluster
      parent: k8s-cluster
      
    # Applications in sentinel-apps namespace
    - id: demo-web
      label: "Demo Web App\n(Vulnerable Flask)"
      style: application
      parent: ns-apps
      
    - id: postgres
      label: "PostgreSQL\nDatabase"
      style: application
      parent: ns-apps
      
    # Security components in sentinel-security namespace
    - id: falco
      label: "Falco\nRuntime Security"
      style: security-component
      parent: ns-security
      
    - id: opa
      label: "OPA Gatekeeper\nPolicy Engine"
      style: security-component
      parent: ns-security
      
    # Monitoring components
    - id: prometheus
      label: "Prometheus\nMetrics Collection"
      style: monitoring-component
      parent: ns-monitoring
      
    - id: grafana
      label: "Grafana\nVisualization"
      style: monitoring-component
      parent: ns-monitoring
      
    - id: elk
      label: "ELK Stack\nLog Aggregation"
      style: monitoring-component
      parent: ns-monitoring
      
    # Vault for secrets management
    - id: vault
      label: "HashiCorp Vault\nSecrets Management"
      style: security-component
      parent: ns-vault
      
    # External security scanning tools
    - id: trivy
      label: "Trivy\nContainer Scanner"
      style: security-component
      
    - id: checkov
      label: "Checkov\nIaC Scanner"
      style: security-component
      
    - id: snyk
      label: "Snyk\nDependency Scanner"
      style: security-component
      
    # Cloud Services (conditional based on deployment)
    - id: cloud-security
      label: "Cloud Security\nGuardDuty/Defender"
      style: external-service
      
    - id: cloud-registry
      label: "Container Registry\nECR/ACR/GCR"
      style: external-service

  # Define connections between components
  edges:
    # Developer workflow
    - from: developer
      to: cicd
      label: "git push"
      
    - from: cicd
      to: trivy
      label: "scan images"
      
    - from: cicd
      to: checkov
      label: "scan IaC"
      
    - from: cicd
      to: snyk
      label: "scan deps"
      
    - from: cicd
      to: cloud-registry
      label: "push images"
      
    - from: cloud-registry
      to: k8s-cluster
      label: "pull images"
      
    # Application connections
    - from: demo-web
      to: postgres
      label: "database\nconnection"
      
    - from: demo-web
      to: vault
      label: "fetch\nsecrets"
      
    # Security monitoring
    - from: falco
      to: prometheus
      label: "security\nmetrics"
      
    - from: falco
      to: elk
      label: "security\nlogs"
      
    - from: opa
      to: prometheus
      label: "policy\nmetrics"
      
    # Monitoring connections
    - from: prometheus
      to: grafana
      label: "metrics\nquery"
      
    - from: elk
      to: grafana
      label: "log\nvisualization"
      
    # Cloud security integration
    - from: k8s-cluster
      to: cloud-security
      label: "threat\ndetection"
      
    # Security scanning of running workloads
    - from: trivy
      to: k8s-cluster
      label: "runtime\nscanning"

  # Add annotations for key security features
  annotations:
    - position: {x: 100, y: 50}
      text: "Multi-layered Security:\n• Runtime Protection\n• Policy Enforcement\n• Vulnerability Scanning\n• Secrets Management"
      
    - position: {x: 500, y: 50}
      text: "Compliance Frameworks:\n• CIS Kubernetes Benchmark\n• NIST Cybersecurity Framework\n• ISO 27001:2013\n• GDPR & HIPAA Ready"
```

## 🛡️ Security-Focused Architecture Prompt

### Prompt for Security Architecture View

```yaml
apiVersion: eraserdiagram.io/v1alpha1
kind: Diagram
metadata:
  name: sentinel-security-architecture
spec:
  title: "Project Sentinel - Security Architecture"
  description: "Detailed view of security components and data flows"
  
  layout:
    direction: LR  # Left to Right for security flow
    
  styles:
    - name: threat-detection
      fillColor: "#DC2626"
      shape: "hexagon"
      
    - name: policy-enforcement
      fillColor: "#7C2D12"
      shape: "diamond"
      
    - name: vulnerability-management
      fillColor: "#BE185D"
      shape: "rectangle"
      
    - name: secrets-management
      fillColor: "#1E40AF"
      shape: "cylinder"
      
    - name: compliance
      fillColor: "#059669"
      shape: "ellipse"

  nodes:
    # Threat Detection Layer
    - id: runtime-threats
      label: "Runtime Threat\nDetection"
      style: threat-detection
      
    - id: falco-rules
      label: "Falco Custom\nSecurity Rules"
      style: threat-detection
      parent: runtime-threats
      
    - id: behavioral-analysis
      label: "Behavioral\nAnalysis Engine"
      style: threat-detection
      parent: runtime-threats
      
    # Policy Enforcement Layer
    - id: policy-engine
      label: "Policy Enforcement\nEngine"
      style: policy-enforcement
      
    - id: admission-control
      label: "OPA Gatekeeper\nAdmission Control"
      style: policy-enforcement
      parent: policy-engine
      
    - id: network-policies
      label: "Network Security\nPolicies"
      style: policy-enforcement
      parent: policy-engine
      
    # Vulnerability Management
    - id: vuln-scanning
      label: "Vulnerability\nScanning"
      style: vulnerability-management
      
    - id: image-scanning
      label: "Container Image\nScanning"
      style: vulnerability-management
      parent: vuln-scanning
      
    - id: iac-scanning
      label: "Infrastructure\nCode Scanning"
      style: vulnerability-management
      parent: vuln-scanning
      
    - id: dependency-scanning
      label: "Dependency\nScanning"
      style: vulnerability-management
      parent: vuln-scanning
      
    # Secrets Management
    - id: secrets-vault
      label: "Centralized\nSecrets Vault"
      style: secrets-management
      
    - id: dynamic-secrets
      label: "Dynamic Database\nCredentials"
      style: secrets-management
      parent: secrets-vault
      
    - id: encryption-keys
      label: "Encryption Key\nManagement"
      style: secrets-management
      parent: secrets-vault
      
    # Compliance Engine
    - id: compliance-engine
      label: "Compliance\nAutomation Engine"
      style: compliance
      
    - id: cis-benchmark
      label: "CIS Kubernetes\nBenchmark"
      style: compliance
      parent: compliance-engine
      
    - id: nist-framework
      label: "NIST Cybersecurity\nFramework"
      style: compliance
      parent: compliance-engine
      
    - id: iso27001
      label: "ISO 27001:2013\nControls"
      style: compliance
      parent: compliance-engine

  edges:
    # Security data flows
    - from: runtime-threats
      to: policy-engine
      label: "threat\nintelligence"
      
    - from: vuln-scanning
      to: policy-engine
      label: "vulnerability\ndata"
      
    - from: policy-engine
      to: compliance-engine
      label: "policy\nviolations"
      
    - from: secrets-vault
      to: runtime-threats
      label: "secure\ncommunication"
      
    # Feedback loops
    - from: compliance-engine
      to: policy-engine
      label: "compliance\nrequirements"
      style: dashed
      
    - from: runtime-threats
      to: vuln-scanning
      label: "threat\nindicators"
      style: dashed

  annotations:
    - text: "Zero Trust Architecture:\nNever trust, always verify"
      position: {x: 100, y: 100}
      
    - text: "Defense in Depth:\nMultiple security layers"
      position: {x: 300, y: 100}
```

## 🌐 Network Security Architecture Prompt

### Prompt for Network Security View

```yaml
apiVersion: eraserdiagram.io/v1alpha1
kind: Diagram
metadata:
  name: sentinel-network-security
spec:
  title: "Project Sentinel - Network Security Architecture"
  description: "Network segmentation and security controls"
  
  layout:
    direction: TB
    
  styles:
    - name: external-zone
      fillColor: "#DC2626"
      borderStyle: "dashed"
      
    - name: dmz-zone
      fillColor: "#F59E0B"
      borderStyle: "solid"
      
    - name: internal-zone
      fillColor: "#059669"
      borderStyle: "solid"
      
    - name: secure-zone
      fillColor: "#1E40AF"
      borderStyle: "double"
      
    - name: firewall
      fillColor: "#7C2D12"
      shape: "diamond"

  nodes:
    # External Zone (Internet)
    - id: internet
      label: "Internet\n(Untrusted)"
      style: external-zone
      
    - id: external-users
      label: "External Users\n& Attackers"
      style: external-zone
      parent: internet
      
    # DMZ Zone
    - id: dmz
      label: "DMZ Zone\n(Perimeter)"
      style: dmz-zone
      
    - id: load-balancer
      label: "Load Balancer\n(ALB/App Gateway)"
      style: dmz-zone
      parent: dmz
      
    - id: waf
      label: "Web Application\nFirewall"
      style: firewall
      parent: dmz
      
    # Internal Zone (Kubernetes Cluster)
    - id: k8s-internal
      label: "Kubernetes Cluster\n(Internal Network)"
      style: internal-zone
      
    - id: app-pods
      label: "Application Pods\n(Demo Web, DB)"
      style: internal-zone
      parent: k8s-internal
      
    - id: monitoring-pods
      label: "Monitoring Pods\n(Prometheus, Grafana)"
      style: internal-zone
      parent: k8s-internal
      
    # Secure Zone (Security Services)
    - id: security-zone
      label: "Security Zone\n(Highly Protected)"
      style: secure-zone
      
    - id: vault-cluster
      label: "Vault Cluster\n(Secrets)"
      style: secure-zone
      parent: security-zone
      
    - id: security-monitoring
      label: "Security Monitoring\n(Falco, OPA)"
      style: secure-zone
      parent: security-zone
      
    # Network Security Controls
    - id: ingress-controller
      label: "Ingress Controller\n(NGINX/Istio)"
      style: firewall
      
    - id: network-policies
      label: "Kubernetes\nNetwork Policies"
      style: firewall
      
    - id: service-mesh
      label: "Service Mesh\n(mTLS)"
      style: firewall

  edges:
    # Traffic flow from external to internal
    - from: external-users
      to: waf
      label: "HTTPS\nTraffic"
      
    - from: waf
      to: load-balancer
      label: "Filtered\nTraffic"
      
    - from: load-balancer
      to: ingress-controller
      label: "Load\nBalanced"
      
    - from: ingress-controller
      to: app-pods
      label: "Routed\nTraffic"
      
    # Internal secure communications
    - from: app-pods
      to: vault-cluster
      label: "Secure\nAPI Calls"
      style: encrypted
      
    - from: security-monitoring
      to: app-pods
      label: "Security\nMonitoring"
      style: dashed
      
    # Network policy enforcement
    - from: network-policies
      to: app-pods
      label: "Traffic\nFiltering"
      style: dashed
      
    - from: service-mesh
      to: app-pods
      label: "mTLS\nEncryption"
      style: encrypted

  annotations:
    - text: "Network Segmentation:\n• External DMZ\n• Internal Cluster\n• Secure Services"
      position: {x: 50, y: 50}
      
    - text: "Security Controls:\n• WAF Protection\n• Network Policies\n• Service Mesh mTLS\n• Zero Trust Network"
      position: {x: 400, y: 50}
```

## 🔄 CI/CD Security Pipeline Prompt

### Prompt for DevSecOps Pipeline Architecture

```yaml
apiVersion: eraserdiagram.io/v1alpha1
kind: Diagram
metadata:
  name: sentinel-devsecops-pipeline
spec:
  title: "Project Sentinel - DevSecOps Pipeline"
  description: "Security-integrated CI/CD pipeline with automated gates"
  
  layout:
    direction: LR
    
  styles:
    - name: development
      fillColor: "#059669"
      
    - name: security-gate
      fillColor: "#DC2626"
      shape: "diamond"
      
    - name: testing
      fillColor: "#7C3AED"
      
    - name: deployment
      fillColor: "#1E40AF"
      
    - name: monitoring
      fillColor: "#F59E0B"

  nodes:
    # Development Phase
    - id: dev-phase
      label: "Development\nPhase"
      style: development
      
    - id: code-commit
      label: "Code Commit\n(Git)"
      style: development
      parent: dev-phase
      
    - id: pre-commit-hooks
      label: "Pre-commit\nSecurity Hooks"
      style: security-gate
      parent: dev-phase
      
    # Security Scanning Phase
    - id: security-scanning
      label: "Security Scanning\nPhase"
      style: security-gate
      
    - id: sast-scan
      label: "SAST\n(Static Analysis)"
      style: security-gate
      parent: security-scanning
      
    - id: dependency-scan
      label: "Dependency\nScanning"
      style: security-gate
      parent: security-scanning
      
    - id: iac-scan
      label: "IaC Security\nScanning"
      style: security-gate
      parent: security-scanning
      
    - id: container-scan
      label: "Container Image\nScanning"
      style: security-gate
      parent: security-scanning
      
    # Testing Phase
    - id: testing-phase
      label: "Testing\nPhase"
      style: testing
      
    - id: unit-tests
      label: "Unit Tests\n& Integration"
      style: testing
      parent: testing-phase
      
    - id: security-tests
      label: "Security Tests\n(DAST)"
      style: security-gate
      parent: testing-phase
      
    # Deployment Phase
    - id: deployment-phase
      label: "Deployment\nPhase"
      style: deployment
      
    - id: policy-check
      label: "Policy\nValidation"
      style: security-gate
      parent: deployment-phase
      
    - id: k8s-deploy
      label: "Kubernetes\nDeployment"
      style: deployment
      parent: deployment-phase
      
    # Runtime Monitoring
    - id: runtime-monitoring
      label: "Runtime\nMonitoring"
      style: monitoring
      
    - id: threat-detection
      label: "Threat Detection\n(Falco)"
      style: security-gate
      parent: runtime-monitoring
      
    - id: compliance-check
      label: "Compliance\nMonitoring"
      style: security-gate
      parent: runtime-monitoring

  edges:
    # Pipeline flow
    - from: code-commit
      to: security-scanning
      label: "trigger\npipeline"
      
    - from: security-scanning
      to: testing-phase
      label: "security\ncleared"
      
    - from: testing-phase
      to: deployment-phase
      label: "tests\npassed"
      
    - from: deployment-phase
      to: runtime-monitoring
      label: "deployed\nsuccessfully"
      
    # Security gates
    - from: sast-scan
      to: code-commit
      label: "fail &\nblock"
      style: dashed
      color: red
      
    - from: container-scan
      to: testing-phase
      label: "vulnerability\nblock"
      style: dashed
      color: red
      
    # Feedback loops
    - from: threat-detection
      to: security-scanning
      label: "threat\nintelligence"
      style: dashed
      
    - from: compliance-check
      to: policy-check
      label: "compliance\nfeedback"
      style: dashed

  annotations:
    - text: "Security Gates:\n• Fail fast on vulnerabilities\n• Block deployment on policy violations\n• Continuous compliance checking"
      position: {x: 200, y: 300}
      
    - text: "Shift Left Security:\n• Early vulnerability detection\n• Automated security testing\n• Developer security training"
      position: {x: 500, y: 300}
```

## 📊 Monitoring and Observability Prompt

### Prompt for Monitoring Architecture

```yaml
apiVersion: eraserdiagram.io/v1alpha1
kind: Diagram
metadata:
  name: sentinel-monitoring-architecture
spec:
  title: "Project Sentinel - Monitoring & Observability"
  description: "Comprehensive monitoring, logging, and alerting architecture"
  
  layout:
    direction: TB
    
  styles:
    - name: data-source
      fillColor: "#7C3AED"
      
    - name: collection
      fillColor: "#059669"
      
    - name: storage
      fillColor: "#1E40AF"
      shape: "cylinder"
      
    - name: visualization
      fillColor: "#F59E0B"
      
    - name: alerting
      fillColor: "#DC2626"

  nodes:
    # Data Sources
    - id: data-sources
      label: "Data Sources"
      style: data-source
      
    - id: k8s-metrics
      label: "Kubernetes\nMetrics"
      style: data-source
      parent: data-sources
      
    - id: app-logs
      label: "Application\nLogs"
      style: data-source
      parent: data-sources
      
    - id: security-events
      label: "Security\nEvents"
      style: data-source
      parent: data-sources
      
    - id: audit-logs
      label: "Audit\nLogs"
      style: data-source
      parent: data-sources
      
    # Collection Layer
    - id: collection-layer
      label: "Collection Layer"
      style: collection
      
    - id: prometheus
      label: "Prometheus\n(Metrics)"
      style: collection
      parent: collection-layer
      
    - id: fluentd
      label: "Fluentd\n(Log Collection)"
      style: collection
      parent: collection-layer
      
    - id: falco-exporter
      label: "Falco Exporter\n(Security Events)"
      style: collection
      parent: collection-layer
      
    # Storage Layer
    - id: storage-layer
      label: "Storage Layer"
      style: storage
      
    - id: prometheus-tsdb
      label: "Prometheus\nTSDB"
      style: storage
      parent: storage-layer
      
    - id: elasticsearch
      label: "Elasticsearch\n(Logs)"
      style: storage
      parent: storage-layer
      
    - id: long-term-storage
      label: "Long-term\nStorage (S3/Blob)"
      style: storage
      parent: storage-layer
      
    # Visualization Layer
    - id: visualization-layer
      label: "Visualization Layer"
      style: visualization
      
    - id: grafana
      label: "Grafana\nDashboards"
      style: visualization
      parent: visualization-layer
      
    - id: kibana
      label: "Kibana\n(Log Analysis)"
      style: visualization
      parent: visualization-layer
      
    - id: security-dashboard
      label: "Security\nDashboard"
      style: visualization
      parent: visualization-layer
      
    # Alerting Layer
    - id: alerting-layer
      label: "Alerting Layer"
      style: alerting
      
    - id: alertmanager
      label: "Alertmanager\n(Prometheus)"
      style: alerting
      parent: alerting-layer
      
    - id: elastalert
      label: "ElastAlert\n(Log Alerts)"
      style: alerting
      parent: alerting-layer
      
    - id: notification-channels
      label: "Notification\nChannels"
      style: alerting
      parent: alerting-layer

  edges:
    # Data flow
    - from: k8s-metrics
      to: prometheus
      label: "scrape\nmetrics"
      
    - from: app-logs
      to: fluentd
      label: "collect\nlogs"
      
    - from: security-events
      to: falco-exporter
      label: "export\nevents"
      
    # Storage connections
    - from: prometheus
      to: prometheus-tsdb
      label: "store\nmetrics"
      
    - from: fluentd
      to: elasticsearch
      label: "index\nlogs"
      
    - from: falco-exporter
      to: prometheus
      label: "security\nmetrics"
      
    # Visualization connections
    - from: prometheus-tsdb
      to: grafana
      label: "query\nmetrics"
      
    - from: elasticsearch
      to: kibana
      label: "search\nlogs"
      
    - from: prometheus-tsdb
      to: security-dashboard
      label: "security\nmetrics"
      
    # Alerting connections
    - from: prometheus
      to: alertmanager
      label: "trigger\nalerts"
      
    - from: elasticsearch
      to: elastalert
      label: "log-based\nalerts"
      
    - from: alertmanager
      to: notification-channels
      label: "send\nnotifications"
      
    - from: elastalert
      to: notification-channels
      label: "send\nnotifications"

  annotations:
    - text: "Three Pillars of Observability:\n• Metrics (Prometheus)\n• Logs (ELK Stack)\n• Traces (Jaeger)"
      position: {x: 100, y: 400}
      
    - text: "Security Monitoring:\n• Real-time threat detection\n• Compliance reporting\n• Incident response automation"
      position: {x: 500, y: 400}
```

## 🎯 Usage Instructions

### How to Use These Prompts with Eraser

1. **Install Eraser:**
   ```bash
   # Install Eraser CLI
   curl -sSL https://github.com/Azure/eraser/releases/latest/download/eraser-linux-amd64.tar.gz | tar -xz
   sudo mv eraser /usr/local/bin/
   ```

2. **Create Diagram:**
   ```bash
   # Save any of the above YAML configurations to a file
   eraser create diagram.yaml
   
   # Generate PNG output
   eraser render diagram.yaml --output diagram.png
   
   # Generate SVG output
   eraser render diagram.yaml --output diagram.svg --format svg
   ```

3. **Customize for Your Environment:**
   - Modify node labels to match your specific deployment
   - Adjust colors and styles to match your organization's branding
   - Add or remove components based on your implementation
   - Update annotations with environment-specific information

4. **Integration with CI/CD:**
   ```yaml
   # Add to GitHub Actions workflow
   - name: Generate Architecture Diagrams
     run: |
       eraser render architecture/*.yaml --output docs/diagrams/
       git add docs/diagrams/
       git commit -m "Update architecture diagrams"
   ```

### Customization Options

**Node Styles:**
- `shape`: rectangle, ellipse, diamond, hexagon, cylinder
- `fillColor`: Hex color codes
- `borderColor`: Border colors
- `borderWidth`: Border thickness
- `textColor`: Text color

**Edge Styles:**
- `style`: solid, dashed, dotted
- `color`: Line color
- `width`: Line thickness
- `arrowType`: arrow, diamond, circle

**Layout Options:**
- `direction`: TB (top-bottom), LR (left-right), BT, RL
- `spacing`: Space between nodes
- `alignment`: Node alignment options

These prompts will generate professional, consistent architecture diagrams that clearly communicate Project Sentinel's security architecture to stakeholders, security teams, and compliance auditors.