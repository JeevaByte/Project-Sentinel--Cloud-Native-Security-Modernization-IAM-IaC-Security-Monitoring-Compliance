#!/bin/bash

# Project Sentinel - Security Scanning Script
# This script runs various security scans on infrastructure and containers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create scan results directory
SCAN_DIR="./scans"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="${SCAN_DIR}/${TIMESTAMP}"

mkdir -p "${RESULTS_DIR}/checkov"
mkdir -p "${RESULTS_DIR}/trivy"
mkdir -p "${RESULTS_DIR}/tfsec"
mkdir -p "${RESULTS_DIR}/snyk"
mkdir -p "${RESULTS_DIR}/kubernetes"

# Function to run Checkov IaC scanning
run_checkov_scan() {
    print_status "Running Checkov infrastructure security scan..."
    
    # Scan Terraform files
    if [ -d "infra/terraform" ]; then
        checkov -d infra/terraform \
            --framework terraform \
            --output json \
            --output-file-path "${RESULTS_DIR}/checkov/terraform-scan.json" \
            --soft-fail || true
        
        checkov -d infra/terraform \
            --framework terraform \
            --output cli \
            --output-file-path "${RESULTS_DIR}/checkov/terraform-scan.txt" \
            --soft-fail || true
    fi
    
    # Scan Kubernetes manifests
    if [ -d "k8s" ]; then
        checkov -d k8s \
            --framework kubernetes \
            --output json \
            --output-file-path "${RESULTS_DIR}/checkov/kubernetes-scan.json" \
            --soft-fail || true
        
        checkov -d k8s \
            --framework kubernetes \
            --output cli \
            --output-file-path "${RESULTS_DIR}/checkov/kubernetes-scan.txt" \
            --soft-fail || true
    fi
    
    # Scan Dockerfiles
    if [ -d "demos/apps" ]; then
        checkov -d demos/apps \
            --framework dockerfile \
            --output json \
            --output-file-path "${RESULTS_DIR}/checkov/dockerfile-scan.json" \
            --soft-fail || true
        
        checkov -d demos/apps \
            --framework dockerfile \
            --output cli \
            --output-file-path "${RESULTS_DIR}/checkov/dockerfile-scan.txt" \
            --soft-fail || true
    fi
    
    print_success "Checkov scan completed"
}

# Function to run tfsec scanning
run_tfsec_scan() {
    print_status "Running tfsec Terraform security scan..."
    
    if [ -d "infra/terraform" ]; then
        tfsec infra/terraform \
            --format json \
            --out "${RESULTS_DIR}/tfsec/terraform-scan.json" \
            --soft-fail || true
        
        tfsec infra/terraform \
            --format default \
            --out "${RESULTS_DIR}/tfsec/terraform-scan.txt" \
            --soft-fail || true
        
        # Generate detailed report
        tfsec infra/terraform \
            --format sarif \
            --out "${RESULTS_DIR}/tfsec/terraform-scan.sarif" \
            --soft-fail || true
    fi
    
    print_success "tfsec scan completed"
}

# Function to run Trivy container scanning
run_trivy_scan() {
    print_status "Running Trivy container security scan..."
    
    # Build demo application image
    if [ -f "demos/apps/web-service/Dockerfile" ]; then
        print_status "Building demo web service image..."
        docker build -t sentinel/demo-web-service:latest demos/apps/web-service/
        
        # Scan for vulnerabilities
        trivy image \
            --format json \
            --output "${RESULTS_DIR}/trivy/web-service-vulns.json" \
            sentinel/demo-web-service:latest || true
        
        trivy image \
            --format table \
            --output "${RESULTS_DIR}/trivy/web-service-vulns.txt" \
            sentinel/demo-web-service:latest || true
        
        # Scan for secrets
        trivy image \
            --scanners secret \
            --format json \
            --output "${RESULTS_DIR}/trivy/web-service-secrets.json" \
            sentinel/demo-web-service:latest || true
        
        # Scan for misconfigurations
        trivy image \
            --scanners config \
            --format json \
            --output "${RESULTS_DIR}/trivy/web-service-config.json" \
            sentinel/demo-web-service:latest || true
    fi
    
    # Scan filesystem for secrets
    trivy fs \
        --scanners secret \
        --format json \
        --output "${RESULTS_DIR}/trivy/filesystem-secrets.json" \
        . || true
    
    # Scan Kubernetes cluster (if running)
    if kubectl cluster-info >/dev/null 2>&1; then
        trivy k8s \
            --format json \
            --output "${RESULTS_DIR}/trivy/kubernetes-cluster.json" \
            cluster || true
    fi
    
    print_success "Trivy scan completed"
}

# Function to run Snyk scanning
run_snyk_scan() {
    print_status "Running Snyk security scan..."
    
    # Check if Snyk token is available
    if [ -z "$SNYK_TOKEN" ]; then
        print_warning "SNYK_TOKEN not set, skipping Snyk scans"
        return 0
    fi
    
    # Scan Python dependencies
    if [ -f "demos/apps/web-service/requirements.txt" ]; then
        cd demos/apps/web-service
        
        snyk test \
            --json \
            --file=requirements.txt \
            --package-manager=pip > "../../../${RESULTS_DIR}/snyk/python-deps.json" || true
        
        snyk test \
            --file=requirements.txt \
            --package-manager=pip > "../../../${RESULTS_DIR}/snyk/python-deps.txt" || true
        
        cd - > /dev/null
    fi
    
    # Scan Docker image (if built)
    if docker images | grep -q "sentinel/demo-web-service"; then
        snyk container test \
            --json \
            sentinel/demo-web-service:latest > "${RESULTS_DIR}/snyk/container.json" || true
        
        snyk container test \
            sentinel/demo-web-service:latest > "${RESULTS_DIR}/snyk/container.txt" || true
    fi
    
    # Scan IaC
    if [ -d "infra/terraform" ]; then
        snyk iac test \
            --json \
            infra/terraform > "${RESULTS_DIR}/snyk/iac.json" || true
        
        snyk iac test \
            infra/terraform > "${RESULTS_DIR}/snyk/iac.txt" || true
    fi
    
    print_success "Snyk scan completed"
}

# Function to run Kubernetes security scanning
run_kubernetes_scan() {
    print_status "Running Kubernetes security scan..."
    
    # Check if cluster is running
    if ! kubectl cluster-info >/dev/null 2>&1; then
        print_warning "Kubernetes cluster not accessible, skipping K8s scans"
        return 0
    fi
    
    # Scan with kube-score
    if command -v kube-score >/dev/null 2>&1; then
        find k8s -name "*.yaml" -o -name "*.yml" | while read -r file; do
            filename=$(basename "$file" .yaml)
            kube-score score "$file" > "${RESULTS_DIR}/kubernetes/kube-score-${filename}.txt" 2>&1 || true
        done
    fi
    
    # Scan with Polaris
    if command -v polaris >/dev/null 2>&1; then
        polaris audit \
            --audit-path k8s/ \
            --format json > "${RESULTS_DIR}/kubernetes/polaris-audit.json" || true
        
        polaris audit \
            --audit-path k8s/ \
            --format pretty > "${RESULTS_DIR}/kubernetes/polaris-audit.txt" || true
    fi
    
    # Check RBAC permissions
    kubectl auth can-i --list --as=system:serviceaccount:sentinel-apps:demo-web-service-sa > "${RESULTS_DIR}/kubernetes/rbac-permissions.txt" 2>&1 || true
    
    # Get security contexts
    kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{": "}{.spec.securityContext}{"\n"}{end}' > "${RESULTS_DIR}/kubernetes/security-contexts.txt" 2>&1 || true
    
    # Get network policies
    kubectl get networkpolicies -A -o yaml > "${RESULTS_DIR}/kubernetes/network-policies.yaml" 2>&1 || true
    
    print_success "Kubernetes security scan completed"
}

# Function to run secret detection
run_secret_detection() {
    print_status "Running secret detection scan..."
    
    # TruffleHog for secret detection
    if command -v trufflehog >/dev/null 2>&1; then
        trufflehog filesystem . \
            --json \
            --output "${RESULTS_DIR}/secrets/trufflehog.json" || true
    fi
    
    # GitLeaks for secret detection
    if command -v gitleaks >/dev/null 2>&1; then
        gitleaks detect \
            --source . \
            --format json \
            --report-path "${RESULTS_DIR}/secrets/gitleaks.json" \
            --no-git || true
    fi
    
    # Custom secret patterns
    grep -r -i -n -E "(password|passwd|pwd|secret|key|token|api_key)" \
        --include="*.py" \
        --include="*.yaml" \
        --include="*.yml" \
        --include="*.tf" \
        --include="*.sh" \
        --include="*.env" \
        . > "${RESULTS_DIR}/secrets/custom-patterns.txt" 2>/dev/null || true
    
    print_success "Secret detection completed"
}

# Function to generate summary report
generate_summary_report() {
    print_status "Generating security scan summary..."
    
    local summary_file="${RESULTS_DIR}/security-summary.txt"
    
    cat > "$summary_file" << EOF
=================================================================
                  SECURITY SCAN SUMMARY
=================================================================
Scan Date: $(date)
Project: Project Sentinel - Enterprise Cloud Security
Scan Directory: ${RESULTS_DIR}

=================================================================
                     SCAN RESULTS
=================================================================

EOF
    
    # Checkov summary
    if [ -f "${RESULTS_DIR}/checkov/terraform-scan.json" ]; then
        echo "CHECKOV (Infrastructure as Code):" >> "$summary_file"
        jq -r '.results.failed_checks | length' "${RESULTS_DIR}/checkov/terraform-scan.json" 2>/dev/null | xargs -I {} echo "  - Failed checks: {}" >> "$summary_file" || echo "  - Failed to parse results" >> "$summary_file"
        echo "" >> "$summary_file"
    fi
    
    # Trivy summary
    if [ -f "${RESULTS_DIR}/trivy/web-service-vulns.json" ]; then
        echo "TRIVY (Container Vulnerabilities):" >> "$summary_file"
        jq -r '.Results[]?.Vulnerabilities | length' "${RESULTS_DIR}/trivy/web-service-vulns.json" 2>/dev/null | awk '{sum+=$1} END {print "  - Total vulnerabilities: " (sum ? sum : 0)}' >> "$summary_file" || echo "  - Failed to parse results" >> "$summary_file"
        echo "" >> "$summary_file"
    fi
    
    # tfsec summary
    if [ -f "${RESULTS_DIR}/tfsec/terraform-scan.json" ]; then
        echo "TFSEC (Terraform Security):" >> "$summary_file"
        jq -r '.results | length' "${RESULTS_DIR}/tfsec/terraform-scan.json" 2>/dev/null | xargs -I {} echo "  - Security issues: {}" >> "$summary_file" || echo "  - Failed to parse results" >> "$summary_file"
        echo "" >> "$summary_file"
    fi
    
    echo "==================================================================" >> "$summary_file"
    echo "For detailed results, check individual scan files in:" >> "$summary_file"
    echo "${RESULTS_DIR}" >> "$summary_file"
    echo "==================================================================" >> "$summary_file"
    
    print_success "Summary report generated: $summary_file"
}

# Function to display results
display_results() {
    print_success "🔍 Security scan completed!"
    echo
    print_status "Scan results saved to: ${RESULTS_DIR}"
    echo
    print_status "Quick summary:"
    
    # Count issues from various scans
    local total_issues=0
    
    # Count Checkov issues
    if [ -f "${RESULTS_DIR}/checkov/terraform-scan.json" ]; then
        local checkov_issues=$(jq -r '.results.failed_checks | length' "${RESULTS_DIR}/checkov/terraform-scan.json" 2>/dev/null || echo "0")
        echo "  📋 Checkov (IaC): $checkov_issues issues"
        total_issues=$((total_issues + checkov_issues))
    fi
    
    # Count Trivy vulnerabilities
    if [ -f "${RESULTS_DIR}/trivy/web-service-vulns.json" ]; then
        local trivy_vulns=$(jq -r '.Results[]?.Vulnerabilities | length' "${RESULTS_DIR}/trivy/web-service-vulns.json" 2>/dev/null | awk '{sum+=$1} END {print (sum ? sum : 0)}')
        echo "  🐳 Trivy (Containers): $trivy_vulns vulnerabilities"
        total_issues=$((total_issues + trivy_vulns))
    fi
    
    # Count tfsec issues
    if [ -f "${RESULTS_DIR}/tfsec/terraform-scan.json" ]; then
        local tfsec_issues=$(jq -r '.results | length' "${RESULTS_DIR}/tfsec/terraform-scan.json" 2>/dev/null || echo "0")
        echo "  🔧 tfsec (Terraform): $tfsec_issues issues"
        total_issues=$((total_issues + tfsec_issues))
    fi
    
    echo
    if [ $total_issues -gt 0 ]; then
        print_warning "⚠️  Total security issues found: $total_issues"
        echo
        print_status "This is expected for the demo environment which contains intentional vulnerabilities."
    else
        print_success "✅ No major issues detected"
    fi
    
    echo
    print_status "View detailed results:"
    echo "  cat ${RESULTS_DIR}/security-summary.txt"
    echo
    print_status "Open HTML reports (if generated):"
    echo "  open ${RESULTS_DIR}/*/*.html"
}

# Main scanning function
main() {
    echo
    print_status "🔍 Starting comprehensive security scan..."
    echo
    
    # Check prerequisites
    print_status "Checking scan tools availability..."
    local missing_tools=()
    
    command -v checkov >/dev/null 2>&1 || missing_tools+=("checkov")
    command -v trivy >/dev/null 2>&1 || missing_tools+=("trivy")
    command -v tfsec >/dev/null 2>&1 || missing_tools+=("tfsec")
    command -v docker >/dev/null 2>&1 || missing_tools+=("docker")
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_warning "Missing tools: ${missing_tools[*]}"
        print_status "Install missing tools or run ./scripts/setup.sh"
    fi
    
    echo
    
    # Run scans
    run_checkov_scan
    echo
    
    run_tfsec_scan
    echo
    
    run_trivy_scan
    echo
    
    run_snyk_scan
    echo
    
    run_kubernetes_scan
    echo
    
    run_secret_detection
    echo
    
    generate_summary_report
    echo
    
    display_results
}

# Handle script arguments
case "${1:-all}" in
    checkov)
        run_checkov_scan
        ;;
    trivy)
        run_trivy_scan
        ;;
    tfsec)
        run_tfsec_scan
        ;;
    snyk)
        run_snyk_scan
        ;;
    k8s)
        run_kubernetes_scan
        ;;
    secrets)
        run_secret_detection
        ;;
    all)
        main
        ;;
    *)
        echo "Usage: $0 [checkov|trivy|tfsec|snyk|k8s|secrets|all]"
        exit 1
        ;;
esac