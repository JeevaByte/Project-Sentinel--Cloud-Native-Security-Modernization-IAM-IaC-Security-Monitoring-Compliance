# Project Sentinel - Mermaid Architecture Diagrams

This document provides comprehensive Mermaid diagram syntax for visualizing Project Sentinel's architecture across multiple views and perspectives.

## 🎯 Overview

Mermaid is a powerful diagramming tool that creates diagrams from text definitions. These diagrams can be rendered in GitHub, GitLab, documentation sites, and many other platforms.

## 🏗️ Main System Architecture

### Complete System Overview

```mermaid
graph TB
    %% External Components
    DEV[👨‍💻 Security Team<br/>& Developers]
    CICD[🔄 CI/CD Pipeline<br/>GitHub Actions]
    CLOUD_REG[📦 Container Registry<br/>ECR/ACR/GCR]
    CLOUD_SEC[☁️ Cloud Security<br/>GuardDuty/Defender]
    
    %% Kubernetes Cluster
    subgraph K8S ["🎯 Kubernetes Cluster (kind/EKS/AKS/GKE)"]
        direction TB
        
        %% Namespaces
        subgraph NS_APPS ["📱 sentinel-apps namespace"]
            DEMO[🌐 Demo Web App<br/>Vulnerable Flask]
            POSTGRES[🗄️ PostgreSQL<br/>Database]
        end
        
        subgraph NS_SEC ["🛡️ sentinel-security namespace"]
            FALCO[👁️ Falco<br/>Runtime Security]
            OPA[📋 OPA Gatekeeper<br/>Policy Engine]
        end
        
        subgraph NS_MON ["📊 monitoring namespace"]
            PROM[📈 Prometheus<br/>Metrics Collection]
            GRAFANA[📊 Grafana<br/>Visualization]
            ELK[📝 ELK Stack<br/>Log Aggregation]
        end
        
        subgraph NS_VAULT ["🔐 vault namespace"]
            VAULT[🔑 HashiCorp Vault<br/>Secrets Management]
        end
    end
    
    %% Security Scanning Tools
    subgraph SCAN_TOOLS ["🔍 Security Scanning Tools"]
        TRIVY[🛡️ Trivy<br/>Container Scanner]
        CHECKOV[📋 Checkov<br/>IaC Scanner]
        SNYK[🔗 Snyk<br/>Dependency Scanner]
    end
    
    %% Connections
    DEV -->|git push| CICD
    CICD -->|scan images| TRIVY
    CICD -->|scan IaC| CHECKOV
    CICD -->|scan deps| SNYK
    CICD -->|push images| CLOUD_REG
    CLOUD_REG -->|pull images| K8S
    
    %% Application connections
    DEMO -->|database queries| POSTGRES
    DEMO -->|fetch secrets| VAULT
    
    %% Security monitoring
    FALCO -->|security metrics| PROM
    FALCO -->|security logs| ELK
    OPA -->|policy metrics| PROM
    
    %% Monitoring connections
    PROM -->|metrics query| GRAFANA
    ELK -->|log visualization| GRAFANA
    
    %% Cloud integration
    K8S -->|threat detection| CLOUD_SEC
    TRIVY -->|runtime scanning| K8S
    
    %% Styling
    classDef kubernetes fill:#326CE5,stroke:#1E3A8A,stroke-width:2px,color:#fff
    classDef security fill:#DC2626,stroke:#991B1B,stroke-width:2px,color:#fff
    classDef monitoring fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    classDef application fill:#7C3AED,stroke:#5B21B6,stroke-width:2px,color:#fff
    classDef external fill:#F59E0B,stroke:#D97706,stroke-width:2px,color:#fff
    
    class K8S,NS_APPS,NS_SEC,NS_MON,NS_VAULT kubernetes
    class FALCO,OPA,VAULT,TRIVY,CHECKOV,SNYK,CLOUD_SEC security
    class PROM,GRAFANA,ELK monitoring
    class DEMO,POSTGRES application
    class DEV,CICD,CLOUD_REG external
```

## 🛡️ Security Architecture Flow

### Security Components and Data Flow

```mermaid
flowchart LR
    %% Threat Detection Layer
    subgraph THREAT ["🚨 Threat Detection Layer"]
        direction TB
        RUNTIME[⚡ Runtime Threat Detection]
        FALCO_RULES[📜 Falco Custom Rules]
        BEHAVIOR[🧠 Behavioral Analysis]
        
        RUNTIME --> FALCO_RULES
        RUNTIME --> BEHAVIOR
    end
    
    %% Policy Enforcement Layer
    subgraph POLICY ["📋 Policy Enforcement Layer"]
        direction TB
        POLICY_ENGINE[⚖️ Policy Engine]
        ADMISSION[🚪 Admission Control]
        NETWORK_POL[🌐 Network Policies]
        
        POLICY_ENGINE --> ADMISSION
        POLICY_ENGINE --> NETWORK_POL
    end
    
    %% Vulnerability Management
    subgraph VULN ["🔍 Vulnerability Management"]
        direction TB
        VULN_SCAN[🛡️ Vulnerability Scanning]
        IMAGE_SCAN[📦 Image Scanning]
        IAC_SCAN[🏗️ IaC Scanning]
        DEP_SCAN[🔗 Dependency Scanning]
        
        VULN_SCAN --> IMAGE_SCAN
        VULN_SCAN --> IAC_SCAN
        VULN_SCAN --> DEP_SCAN
    end
    
    %% Secrets Management
    subgraph SECRETS ["🔐 Secrets Management"]
        direction TB
        VAULT_CENTRAL[🏦 Centralized Vault]
        DYNAMIC_CREDS[🔄 Dynamic Credentials]
        ENCRYPTION[🔑 Encryption Keys]
        
        VAULT_CENTRAL --> DYNAMIC_CREDS
        VAULT_CENTRAL --> ENCRYPTION
    end
    
    %% Compliance Engine
    subgraph COMPLIANCE ["✅ Compliance Engine"]
        direction TB
        COMP_ENGINE[🎯 Compliance Automation]
        CIS[📊 CIS Benchmark]
        NIST[🏛️ NIST Framework]
        ISO[📋 ISO 27001]
        
        COMP_ENGINE --> CIS
        COMP_ENGINE --> NIST
        COMP_ENGINE --> ISO
    end
    
    %% Security Data Flows
    THREAT -.->|threat intelligence| POLICY
    VULN -.->|vulnerability data| POLICY
    POLICY -.->|policy violations| COMPLIANCE
    SECRETS -.->|secure communication| THREAT
    
    %% Feedback Loops
    COMPLIANCE -.->|requirements| POLICY
    THREAT -.->|indicators| VULN
    
    %% Styling
    classDef threatClass fill:#DC2626,stroke:#991B1B,stroke-width:2px,color:#fff
    classDef policyClass fill:#7C2D12,stroke:#451A03,stroke-width:2px,color:#fff
    classDef vulnClass fill:#BE185D,stroke:#831843,stroke-width:2px,color:#fff
    classDef secretsClass fill:#1E40AF,stroke:#1E3A8A,stroke-width:2px,color:#fff
    classDef complianceClass fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    
    class THREAT,RUNTIME,FALCO_RULES,BEHAVIOR threatClass
    class POLICY,POLICY_ENGINE,ADMISSION,NETWORK_POL policyClass
    class VULN,VULN_SCAN,IMAGE_SCAN,IAC_SCAN,DEP_SCAN vulnClass
    class SECRETS,VAULT_CENTRAL,DYNAMIC_CREDS,ENCRYPTION secretsClass
    class COMPLIANCE,COMP_ENGINE,CIS,NIST,ISO complianceClass
```

## 🌐 Network Security Architecture

### Network Segmentation and Security Controls

```mermaid
graph TB
    %% External Zone
    subgraph EXTERNAL ["🌍 External Zone (Untrusted)"]
        INTERNET[🌐 Internet]
        USERS[👥 External Users & Attackers]
        INTERNET --> USERS
    end
    
    %% DMZ Zone
    subgraph DMZ ["🛡️ DMZ Zone (Perimeter)"]
        direction TB
        LB[⚖️ Load Balancer<br/>ALB/App Gateway]
        WAF[🔥 Web Application<br/>Firewall]
        
        WAF --> LB
    end
    
    %% Kubernetes Network
    subgraph K8S_NET ["🎯 Kubernetes Network (Internal)"]
        direction TB
        INGRESS[🚪 Ingress Controller<br/>NGINX/Istio]
        
        subgraph APP_ZONE ["📱 Application Zone"]
            APP_PODS[🏃 Application Pods<br/>Demo Web, DB]
        end
        
        subgraph MON_ZONE ["📊 Monitoring Zone"]
            MON_PODS[👁️ Monitoring Pods<br/>Prometheus, Grafana]
        end
        
        INGRESS --> APP_PODS
        INGRESS --> MON_PODS
    end
    
    %% Security Zone
    subgraph SEC_ZONE ["🔒 Security Zone (Highly Protected)"]
        direction TB
        VAULT_CLUSTER[🏦 Vault Cluster<br/>Secrets]
        SEC_MON[🛡️ Security Monitoring<br/>Falco, OPA]
        
        VAULT_CLUSTER -.-> SEC_MON
    end
    
    %% Network Security Controls
    subgraph NET_CONTROLS ["🔧 Network Security Controls"]
        NET_POL[📋 Network Policies]
        SERVICE_MESH[🕸️ Service Mesh (mTLS)]
        FIREWALL_RULES[🔥 Firewall Rules]
    end
    
    %% Traffic Flow
    USERS -->|HTTPS Traffic| WAF
    WAF -->|Filtered Traffic| LB
    LB -->|Load Balanced| INGRESS
    INGRESS -->|Routed Traffic| APP_PODS
    
    %% Secure Communications
    APP_PODS -.->|Secure API| VAULT_CLUSTER
    SEC_MON -.->|Monitoring| APP_PODS
    SEC_MON -.->|Monitoring| MON_PODS
    
    %% Security Controls
    NET_POL -.->|Traffic Filtering| APP_PODS
    SERVICE_MESH -.->|mTLS Encryption| APP_PODS
    FIREWALL_RULES -.->|Access Control| K8S_NET
    
    %% Styling
    classDef external fill:#DC2626,stroke:#991B1B,stroke-width:3px,color:#fff
    classDef dmz fill:#F59E0B,stroke:#D97706,stroke-width:2px,color:#fff
    classDef internal fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    classDef secure fill:#1E40AF,stroke:#1E3A8A,stroke-width:3px,color:#fff
    classDef controls fill:#7C2D12,stroke:#451A03,stroke-width:2px,color:#fff
    
    class EXTERNAL,INTERNET,USERS external
    class DMZ,LB,WAF dmz
    class K8S_NET,APP_ZONE,MON_ZONE,INGRESS,APP_PODS,MON_PODS internal
    class SEC_ZONE,VAULT_CLUSTER,SEC_MON secure
    class NET_CONTROLS,NET_POL,SERVICE_MESH,FIREWALL_RULES controls
```

## 🔄 DevSecOps Pipeline

### Security-Integrated CI/CD Pipeline

```mermaid
flowchart LR
    %% Development Phase
    subgraph DEV ["💻 Development Phase"]
        direction TB
        CODE_COMMIT[📝 Code Commit<br/>Git]
        PRE_COMMIT[🔒 Pre-commit<br/>Security Hooks]
        
        CODE_COMMIT --> PRE_COMMIT
    end
    
    %% Security Scanning Phase
    subgraph SCAN ["🔍 Security Scanning Phase"]
        direction TB
        SAST[🔍 SAST<br/>Static Analysis]
        DEP_SCAN[🔗 Dependency<br/>Scanning]
        IAC_SCAN[🏗️ IaC Security<br/>Scanning]
        CONTAINER_SCAN[📦 Container<br/>Scanning]
        
        SAST --> DEP_SCAN
        DEP_SCAN --> IAC_SCAN
        IAC_SCAN --> CONTAINER_SCAN
    end
    
    %% Testing Phase
    subgraph TEST ["🧪 Testing Phase"]
        direction TB
        UNIT_TESTS[✅ Unit Tests &<br/>Integration]
        DAST[🎯 DAST<br/>Security Tests]
        
        UNIT_TESTS --> DAST
    end
    
    %% Deployment Phase
    subgraph DEPLOY ["🚀 Deployment Phase"]
        direction TB
        POLICY_CHECK[📋 Policy<br/>Validation]
        K8S_DEPLOY[⚙️ Kubernetes<br/>Deployment]
        
        POLICY_CHECK --> K8S_DEPLOY
    end
    
    %% Runtime Monitoring
    subgraph RUNTIME ["👁️ Runtime Monitoring"]
        direction TB
        THREAT_DETECT[🚨 Threat Detection<br/>Falco]
        COMPLIANCE_MON[✅ Compliance<br/>Monitoring]
        
        THREAT_DETECT --> COMPLIANCE_MON
    end
    
    %% Pipeline Flow
    DEV -->|Pipeline Trigger| SCAN
    SCAN -->|Security Cleared| TEST
    TEST -->|Tests Passed| DEPLOY
    DEPLOY -->|Deployed Successfully| RUNTIME
    
    %% Security Gates (Failure Paths)
    SCAN -.->|Vulnerability Block| DEV
    TEST -.->|Security Test Fail| DEV
    DEPLOY -.->|Policy Violation| DEV
    
    %% Feedback Loops
    RUNTIME -.->|Threat Intelligence| SCAN
    RUNTIME -.->|Compliance Feedback| DEPLOY
    
    %% Security Gate Indicators
    GATE1{🚫 Security Gate}
    GATE2{🚫 Security Gate}
    GATE3{🚫 Security Gate}
    
    SCAN --- GATE1
    TEST --- GATE2
    DEPLOY --- GATE3
    
    %% Styling
    classDef development fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    classDef security fill:#DC2626,stroke:#991B1B,stroke-width:2px,color:#fff
    classDef testing fill:#7C3AED,stroke:#5B21B6,stroke-width:2px,color:#fff
    classDef deployment fill:#1E40AF,stroke:#1E3A8A,stroke-width:2px,color:#fff
    classDef monitoring fill:#F59E0B,stroke:#D97706,stroke-width:2px,color:#fff
    classDef gate fill:#7C2D12,stroke:#451A03,stroke-width:3px,color:#fff
    
    class DEV,CODE_COMMIT,PRE_COMMIT development
    class SCAN,SAST,DEP_SCAN,IAC_SCAN,CONTAINER_SCAN security
    class TEST,UNIT_TESTS,DAST testing
    class DEPLOY,POLICY_CHECK,K8S_DEPLOY deployment
    class RUNTIME,THREAT_DETECT,COMPLIANCE_MON monitoring
    class GATE1,GATE2,GATE3 gate
```

## 📊 Monitoring and Observability

### Three Pillars of Observability

```mermaid
graph TB
    %% Data Sources
    subgraph SOURCES ["📡 Data Sources"]
        direction LR
        K8S_METRICS[📊 Kubernetes Metrics]
        APP_LOGS[📝 Application Logs]
        SEC_EVENTS[🚨 Security Events]
        AUDIT_LOGS[📋 Audit Logs]
    end
    
    %% Collection Layer
    subgraph COLLECTION ["🔄 Collection Layer"]
        direction LR
        PROMETHEUS[📈 Prometheus<br/>Metrics]
        FLUENTD[📥 Fluentd<br/>Log Collection]
        FALCO_EXP[🛡️ Falco Exporter<br/>Security Events]
        JAEGER[🔍 Jaeger<br/>Distributed Tracing]
    end
    
    %% Storage Layer
    subgraph STORAGE ["💾 Storage Layer"]
        direction LR
        PROM_TSDB[(📊 Prometheus TSDB)]
        ELASTICSEARCH[(🔍 Elasticsearch)]
        S3_STORAGE[(☁️ Long-term Storage<br/>S3/Blob)]
        JAEGER_DB[(🔍 Jaeger Storage)]
    end
    
    %% Visualization Layer
    subgraph VISUALIZATION ["📊 Visualization Layer"]
        direction LR
        GRAFANA[📊 Grafana Dashboards]
        KIBANA[🔍 Kibana Log Analysis]
        SEC_DASHBOARD[🛡️ Security Dashboard]
        JAEGER_UI[🔍 Jaeger UI]
    end
    
    %% Alerting Layer
    subgraph ALERTING ["🚨 Alerting Layer"]
        direction LR
        ALERTMANAGER[📢 Alertmanager]
        ELASTALERT[⚡ ElastAlert]
        NOTIFICATION[📱 Notifications<br/>Slack/Email/PagerDuty]
    end
    
    %% Data Flow - Metrics Path
    K8S_METRICS --> PROMETHEUS
    SEC_EVENTS --> FALCO_EXP
    FALCO_EXP --> PROMETHEUS
    PROMETHEUS --> PROM_TSDB
    PROM_TSDB --> GRAFANA
    PROM_TSDB --> SEC_DASHBOARD
    PROMETHEUS --> ALERTMANAGER
    
    %% Data Flow - Logs Path
    APP_LOGS --> FLUENTD
    AUDIT_LOGS --> FLUENTD
    FLUENTD --> ELASTICSEARCH
    ELASTICSEARCH --> KIBANA
    ELASTICSEARCH --> ELASTALERT
    
    %% Data Flow - Tracing Path
    APP_LOGS --> JAEGER
    JAEGER --> JAEGER_DB
    JAEGER_DB --> JAEGER_UI
    
    %% Long-term Storage
    PROM_TSDB --> S3_STORAGE
    ELASTICSEARCH --> S3_STORAGE
    
    %% Alerting
    ALERTMANAGER --> NOTIFICATION
    ELASTALERT --> NOTIFICATION
    
    %% Styling
    classDef sources fill:#7C3AED,stroke:#5B21B6,stroke-width:2px,color:#fff
    classDef collection fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    classDef storage fill:#1E40AF,stroke:#1E3A8A,stroke-width:2px,color:#fff
    classDef visualization fill:#F59E0B,stroke:#D97706,stroke-width:2px,color:#fff
    classDef alerting fill:#DC2626,stroke:#991B1B,stroke-width:2px,color:#fff
    
    class SOURCES,K8S_METRICS,APP_LOGS,SEC_EVENTS,AUDIT_LOGS sources
    class COLLECTION,PROMETHEUS,FLUENTD,FALCO_EXP,JAEGER collection
    class STORAGE,PROM_TSDB,ELASTICSEARCH,S3_STORAGE,JAEGER_DB storage
    class VISUALIZATION,GRAFANA,KIBANA,SEC_DASHBOARD,JAEGER_UI visualization
    class ALERTING,ALERTMANAGER,ELASTALERT,NOTIFICATION alerting
```

## 🏛️ Compliance and Governance

### Compliance Framework Implementation

```mermaid
mindmap
  root((🎯 Project Sentinel<br/>Compliance))
    🏛️ Frameworks
      📊 CIS Kubernetes Benchmark
        🔒 Pod Security Standards
        🌐 Network Security
        🔑 Secrets Management
        👁️ Audit Logging
      🏛️ NIST Cybersecurity Framework
        🎯 Identify
        🛡️ Protect
        🔍 Detect
        🚨 Respond
        🔄 Recover
      📋 ISO 27001:2013
        💼 Information Security Management
        🔒 Access Control
        📊 Risk Assessment
        📈 Continuous Improvement
      ⚖️ Regulatory Compliance
        🇪🇺 GDPR
        🏥 HIPAA
        💳 PCI DSS
        📊 SOX
    🔧 Implementation
      🤖 Automated Compliance Checks
        ✅ Policy Validation
        📊 Continuous Monitoring
        📋 Compliance Reporting
      🔍 Security Controls
        🛡️ Runtime Protection
        🔒 Data Encryption
        👤 Identity Management
        🌐 Network Segmentation
    📊 Monitoring
      📈 Compliance Dashboards
      🚨 Violation Alerts
      📋 Audit Reports
      📊 Risk Metrics
```

## 🎭 Threat Modeling

### STRIDE Threat Analysis

```mermaid
graph LR
    %% Application Components
    subgraph APP ["🌐 Web Application"]
        WEB_APP[📱 Flask Demo App]
        DATABASE[🗄️ PostgreSQL DB]
        API[🔌 REST API]
    end
    
    %% Trust Boundaries
    subgraph TRUST_BOUNDARY ["🛡️ Trust Boundaries"]
        INTERNET_BOUNDARY[🌍 Internet Boundary]
        K8S_BOUNDARY[🎯 Kubernetes Boundary]
        DB_BOUNDARY[🗄️ Database Boundary]
    end
    
    %% STRIDE Threats
    subgraph THREATS ["⚠️ STRIDE Threats"]
        direction TB
        
        subgraph SPOOFING ["🎭 Spoofing"]
            S1[Identity Spoofing]
            S2[Certificate Spoofing]
        end
        
        subgraph TAMPERING ["✏️ Tampering"]
            T1[Code Injection]
            T2[Data Tampering]
        end
        
        subgraph REPUDIATION ["🙈 Repudiation"]
            R1[Log Tampering]
            R2[Action Denial]
        end
        
        subgraph INFO_DISCLOSURE ["👁️ Information Disclosure"]
            I1[Data Exposure]
            I2[Credential Leakage]
        end
        
        subgraph DENIAL_OF_SERVICE ["💥 Denial of Service"]
            D1[Resource Exhaustion]
            D2[Service Disruption]
        end
        
        subgraph ELEVATION ["👑 Elevation of Privilege"]
            E1[Container Escape]
            E2[Privilege Escalation]
        end
    end
    
    %% Mitigations
    subgraph MITIGATIONS ["🛡️ Security Mitigations"]
        direction TB
        
        AUTHENTICATION[🔐 Strong Authentication<br/>OAuth2 + mTLS]
        INPUT_VALIDATION[✅ Input Validation<br/>WAF + API Gateway]
        AUDIT_LOGGING[📝 Comprehensive Logging<br/>Falco + ELK]
        ENCRYPTION[🔒 Data Encryption<br/>TLS + Vault]
        RATE_LIMITING[⏱️ Rate Limiting<br/>Load Balancer]
        RBAC[👤 RBAC + Pod Security<br/>OPA Gatekeeper]
    end
    
    %% Threat to Mitigation Mapping
    SPOOFING -.-> AUTHENTICATION
    TAMPERING -.-> INPUT_VALIDATION
    REPUDIATION -.-> AUDIT_LOGGING
    INFO_DISCLOSURE -.-> ENCRYPTION
    DENIAL_OF_SERVICE -.-> RATE_LIMITING
    ELEVATION -.-> RBAC
    
    %% Component Threats
    WEB_APP -.-> TAMPERING
    API -.-> INFO_DISCLOSURE
    DATABASE -.-> ELEVATION
    
    %% Styling
    classDef app fill:#7C3AED,stroke:#5B21B6,stroke-width:2px,color:#fff
    classDef boundary fill:#F59E0B,stroke:#D97706,stroke-width:2px,color:#fff
    classDef threat fill:#DC2626,stroke:#991B1B,stroke-width:2px,color:#fff
    classDef mitigation fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    
    class APP,WEB_APP,DATABASE,API app
    class TRUST_BOUNDARY,INTERNET_BOUNDARY,K8S_BOUNDARY,DB_BOUNDARY boundary
    class THREATS,SPOOFING,TAMPERING,REPUDIATION,INFO_DISCLOSURE,DENIAL_OF_SERVICE,ELEVATION threat
    class MITIGATIONS,AUTHENTICATION,INPUT_VALIDATION,AUDIT_LOGGING,ENCRYPTION,RATE_LIMITING,RBAC mitigation
```

## 🚀 Deployment Architecture

### Multi-Environment Deployment Strategy

```mermaid
gitgraph
    commit id: "Initial Setup"
    branch development
    checkout development
    commit id: "Dev: Local kind cluster"
    commit id: "Dev: Security tools"
    commit id: "Dev: Monitoring setup"
    
    checkout main
    merge development
    branch staging
    checkout staging
    commit id: "Staging: Cloud deployment"
    commit id: "Staging: Integration tests"
    commit id: "Staging: Security validation"
    
    checkout main
    merge staging
    branch production
    checkout production
    commit id: "Prod: High availability"
    commit id: "Prod: Security hardening"
    commit id: "Prod: Compliance validation"
    
    checkout main
    merge production
    commit id: "Release v1.0"
```

## 📋 Usage Instructions

### How to Use These Mermaid Diagrams

1. **GitHub/GitLab Integration:**
   ```markdown
   # Simply paste the mermaid code blocks into your README.md
   # They will be automatically rendered
   ```

2. **Mermaid Live Editor:**
   - Visit: https://mermaid.live/
   - Paste any diagram code
   - Export as PNG, SVG, or PDF

3. **VS Code Integration:**
   ```bash
   # Install Mermaid Preview extension
   code --install-extension bierner.markdown-mermaid
   ```

4. **Documentation Sites:**
   - **GitBook:** Native Mermaid support
   - **Notion:** Use Mermaid blocks
   - **Confluence:** Mermaid macro available
   - **MkDocs:** mermaid2 plugin

5. **CI/CD Integration:**
   ```yaml
   # GitHub Actions example
   - name: Generate Diagrams
     uses: mermaid-js/mermaid-cli@v1
     with:
       files: 'docs/*.md'
       output: 'docs/diagrams/'
   ```

### Customization Options

**Colors and Themes:**
```mermaid
%%{init: {'theme':'dark', 'themeVariables': { 'primaryColor': '#ff0000'}}}%%
```

**Direction:**
- `TB` - Top to Bottom
- `LR` - Left to Right
- `BT` - Bottom to Top
- `RL` - Right to Left

**Node Shapes:**
- `[]` - Rectangle
- `()` - Round edges
- `{}` - Diamond
- `(())` - Circle
- `[[]]` - Subroutine
- `[()]` - Stadium

These Mermaid diagrams provide a comprehensive visual representation of Project Sentinel's architecture that can be easily integrated into documentation, presentations, and development workflows!