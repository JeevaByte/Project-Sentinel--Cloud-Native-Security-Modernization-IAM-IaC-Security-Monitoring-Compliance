#!/bin/bash
# Project Sentinel - Attack Simulation and Monitoring Integration
# This script demonstrates end-to-end security monitoring by running attacks and showing detections

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Project Sentinel - Security Demonstration ===${NC}"
echo "This script will simulate attacks and show how they're detected"
echo

# Function to check if a pod is running
check_pod_running() {
    local namespace=$1
    local label=$2
    local description=$3
    
    echo -e "${BLUE}Checking $description...${NC}"
    if kubectl get pods -n $namespace -l $label --no-headers | grep -q "Running"; then
        echo -e "${GREEN}✓ $description is running${NC}"
        return 0
    else
        echo -e "${RED}✗ $description is not running${NC}"
        return 1
    fi
}

# Function to wait for logs
wait_for_logs() {
    local namespace=$1
    local label=$2
    local pattern=$3
    local timeout=$4
    
    echo -e "${YELLOW}Waiting for $pattern in logs...${NC}"
    local count=0
    while [ $count -lt $timeout ]; do
        if kubectl logs -n $namespace -l $label --tail=50 | grep -q "$pattern"; then
            return 0
        fi
        sleep 1
        ((count++))
    done
    return 1
}

# Check prerequisites
echo -e "${BLUE}=== Prerequisites Check ===${NC}"

# Check if kind cluster is running
if ! kind get clusters | grep -q "sentinel"; then
    echo -e "${RED}✗ Kind cluster 'sentinel' not found${NC}"
    echo "Please run setup.sh first"
    exit 1
fi
echo -e "${GREEN}✓ Kind cluster 'sentinel' is running${NC}"

# Check critical pods
check_pod_running "sentinel-security" "app=falco" "Falco" || exit 1
check_pod_running "monitoring" "app.kubernetes.io/name=prometheus" "Prometheus" || exit 1
check_pod_running "monitoring" "app=grafana" "Grafana" || exit 1
check_pod_running "sentinel-apps" "app=demo-web" "Demo Web App" || exit 1
check_pod_running "sentinel-apps" "app=postgres" "PostgreSQL" || exit 1

echo
echo -e "${GREEN}✓ All prerequisite services are running${NC}"
echo

# Display monitoring URLs
echo -e "${BLUE}=== Monitoring Dashboards ===${NC}"
echo "Grafana: http://localhost:3000 (admin/admin)"
echo "  - Security Dashboard: http://localhost:3000/d/sentinel_security"
echo "  - Compliance Dashboard: http://localhost:3000/d/sentinel_compliance"
echo "Prometheus: http://localhost:9090"
echo "Demo App: http://localhost:8080"
echo

# Function to show real-time Falco events
show_falco_events() {
    echo -e "${BLUE}=== Falco Security Events (Live) ===${NC}"
    echo "Monitoring Falco events for the next 30 seconds..."
    echo "Press Ctrl+C to stop monitoring and continue"
    kubectl logs -n sentinel-security -l app=falco -f --tail=10 &
    local falco_pid=$!
    sleep 30
    kill $falco_pid 2>/dev/null || true
    echo
}

# Function to run container escape simulation
run_container_escape() {
    echo -e "${BLUE}=== Container Escape Attack Simulation ===${NC}"
    echo "Starting container escape simulation..."
    
    # Make script executable and run it
    chmod +x ./scripts/simulate-container-escape.sh
    
    # Run in background to capture logs
    ./scripts/simulate-container-escape.sh &
    local attack_pid=$!
    
    # Give attack time to start
    sleep 5
    
    # Monitor Falco for container escape detection
    echo -e "${YELLOW}Checking for Falco detections...${NC}"
    if wait_for_logs "sentinel-security" "app=falco" "Container escape" 30; then
        echo -e "${GREEN}✓ Container escape detected by Falco!${NC}"
    else
        echo -e "${YELLOW}⚠ Container escape not detected (check Falco rules)${NC}"
    fi
    
    # Wait for attack to complete
    wait $attack_pid 2>/dev/null || true
    echo
}

# Function to run SQL injection simulation
run_sql_injection() {
    echo -e "${BLUE}=== SQL Injection Attack Simulation ===${NC}"
    echo "Starting SQL injection simulation..."
    
    # Make script executable and run it
    chmod +x ./scripts/simulate-sql-injection.sh
    
    # Run in background to capture logs
    ./scripts/simulate-sql-injection.sh &
    local attack_pid=$!
    
    # Give attack time to start
    sleep 5
    
    # Monitor application logs for suspicious activity
    echo -e "${YELLOW}Checking for application security events...${NC}"
    if kubectl logs -n sentinel-apps -l app=demo-web --tail=20 | grep -q "SELECT\|UNION\|injection"; then
        echo -e "${GREEN}✓ SQL injection attempts logged in application${NC}"
    else
        echo -e "${YELLOW}⚠ SQL injection not logged (check application logging)${NC}"
    fi
    
    # Wait for attack to complete
    wait $attack_pid 2>/dev/null || true
    echo
}

# Function to show security metrics
show_security_metrics() {
    echo -e "${BLUE}=== Security Metrics Summary ===${NC}"
    
    # Query Prometheus for metrics (if available)
    echo "Prometheus metrics:"
    if kubectl get svc -n monitoring prometheus-server &>/dev/null; then
        # Port forward to Prometheus (non-blocking)
        kubectl port-forward -n monitoring svc/prometheus-server 9090:80 &>/dev/null &
        local pf_pid=$!
        sleep 3
        
        # Try to get metrics
        if curl -s http://localhost:9090/api/v1/query?query=up | grep -q "success"; then
            echo "  ✓ Prometheus is accessible"
            # Add more specific metrics queries here
        else
            echo "  ⚠ Unable to query Prometheus metrics"
        fi
        
        kill $pf_pid 2>/dev/null || true
    else
        echo "  ⚠ Prometheus service not found"
    fi
    
    # Show pod status
    echo
    echo "Pod Security Status:"
    kubectl get pods --all-namespaces -o wide | grep -E "(sentinel|monitoring)" | \
        awk '{printf "  %-20s %-15s %-10s %s\n", $2, $1, $4, $7}'
    echo
}

# Function to generate security report
generate_security_report() {
    echo -e "${BLUE}=== Generating Security Report ===${NC}"
    
    local report_file="security-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
PROJECT SENTINEL - SECURITY DEMONSTRATION REPORT
Generated: $(date)
=====================================

ENVIRONMENT STATUS:
- Kind Cluster: sentinel (Running)
- Namespaces: sentinel-apps, sentinel-security, monitoring, vault, keycloak
- Demo Application: Flask Web App with intentional vulnerabilities
- Security Tools: Falco, Prometheus, Grafana, Vault

ATTACK SIMULATIONS EXECUTED:
1. Container Escape Simulation
   - Docker socket access attempts
   - Privilege escalation attempts
   - Suspicious process execution
   - File system access attempts

2. SQL Injection Simulation
   - Union-based injection
   - Boolean-based blind injection
   - Time-based blind injection
   - Error-based injection
   - Authentication bypass attempts

SECURITY DETECTIONS:
$(kubectl logs -n sentinel-security -l app=falco --tail=50 | grep -E "(Critical|High|Warning)" | head -10)

COMPLIANCE STATUS:
- CIS Kubernetes Benchmark: Partial implementation
- NIST Cybersecurity Framework: Monitoring and detection implemented
- ISO 27001: Security controls demonstration

RECOMMENDATIONS:
1. Review Falco rules for comprehensive coverage
2. Implement automated response to critical events
3. Configure alerting to security team
4. Regular vulnerability scanning and patching
5. Security awareness training for development teams

MONITORING DASHBOARDS:
- Grafana Security Dashboard: http://localhost:3000/d/sentinel_security
- Grafana Compliance Dashboard: http://localhost:3000/d/sentinel_compliance
- Prometheus Metrics: http://localhost:9090

EOF

    echo -e "${GREEN}✓ Security report generated: $report_file${NC}"
    echo
}

# Main demonstration flow
main() {
    # Initial setup check
    echo -e "${BLUE}=== Starting Security Demonstration ===${NC}"
    
    # Show current monitoring
    echo "Step 1: Baseline monitoring"
    show_security_metrics
    
    read -p "Press Enter to start attack simulations..."
    
    # Run attack simulations
    echo "Step 2: Attack simulations"
    run_container_escape
    run_sql_injection
    
    read -p "Press Enter to show live security events..."
    
    # Show live monitoring
    echo "Step 3: Security event monitoring"
    show_falco_events
    
    # Generate report
    echo "Step 4: Security reporting"
    generate_security_report
    
    echo -e "${GREEN}=== Security Demonstration Complete ===${NC}"
    echo
    echo "What you've seen:"
    echo "1. ✓ Attack simulations executed"
    echo "2. ✓ Security events detected and logged"
    echo "3. ✓ Real-time monitoring demonstrated"
    echo "4. ✓ Security report generated"
    echo
    echo "Next steps:"
    echo "- Review Grafana dashboards for detailed analysis"
    echo "- Check security report for recommendations"
    echo "- Configure alerting for production deployment"
    echo "- Implement automated incident response"
    echo
    echo -e "${BLUE}Access your monitoring dashboards:${NC}"
    echo "• Grafana: http://localhost:3000"
    echo "• Prometheus: http://localhost:9090"
    echo "• Demo App: http://localhost:8080"
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Demonstration interrupted by user${NC}"; exit 0' INT

# Run main function
main

echo -e "${GREEN}Thank you for exploring Project Sentinel!${NC}"