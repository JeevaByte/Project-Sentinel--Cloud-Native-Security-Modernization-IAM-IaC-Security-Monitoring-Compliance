#!/bin/bash

# Project Sentinel - Setup Script
# This script sets up the local development environment for Project Sentinel

set -e

echo "🛡️  Project Sentinel - Enterprise Cloud Security Setup"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check and install prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Docker
    if command_exists docker; then
        print_success "Docker found: $(docker --version)"
    else
        print_error "Docker not found. Please install Docker Desktop first."
        exit 1
    fi
    
    # Check kubectl
    if command_exists kubectl; then
        print_success "kubectl found: $(kubectl version --client --short 2>/dev/null)"
    else
        print_warning "kubectl not found. Installing..."
        install_kubectl
    fi
    
    # Check kind
    if command_exists kind; then
        print_success "kind found: $(kind version)"
    else
        print_warning "kind not found. Installing..."
        install_kind
    fi
    
    # Check Helm
    if command_exists helm; then
        print_success "Helm found: $(helm version --short)"
    else
        print_warning "Helm not found. Installing..."
        install_helm
    fi
    
    # Check Terraform
    if command_exists terraform; then
        print_success "Terraform found: $(terraform version | head -n1)"
    else
        print_warning "Terraform not found. Installing..."
        install_terraform
    fi
    
    # Check Python
    if command_exists python3; then
        print_success "Python found: $(python3 --version)"
    else
        print_error "Python 3 not found. Please install Python 3.8+."
        exit 1
    fi
}

# Function to install kubectl
install_kubectl() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
        sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/darwin/amd64/kubectl"
        chmod +x ./kubectl
        sudo mv ./kubectl /usr/local/bin/kubectl
    else
        print_error "Unsupported OS for automatic kubectl installation. Please install manually."
        exit 1
    fi
}

# Function to install kind
install_kind() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
        chmod +x ./kind
        sudo mv ./kind /usr/local/bin/kind
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-darwin-amd64
        chmod +x ./kind
        sudo mv ./kind /usr/local/bin/kind
    else
        print_error "Unsupported OS for automatic kind installation. Please install manually."
        exit 1
    fi
}

# Function to install Helm
install_helm() {
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
}

# Function to install Terraform
install_terraform() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
        sudo apt update && sudo apt install terraform
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew tap hashicorp/tap
        brew install hashicorp/tap/terraform
    else
        print_error "Unsupported OS for automatic Terraform installation. Please install manually."
        exit 1
    fi
}

# Function to install security tools
install_security_tools() {
    print_status "Installing security tools..."
    
    # Install Trivy
    if ! command_exists trivy; then
        print_status "Installing Trivy..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            sudo apt-get update
            sudo apt-get install wget apt-transport-https gnupg lsb-release
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
            sudo apt-get update
            sudo apt-get install trivy
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            brew install trivy
        fi
        print_success "Trivy installed"
    fi
    
    # Install Checkov
    if ! command_exists checkov; then
        print_status "Installing Checkov..."
        pip3 install checkov
        print_success "Checkov installed"
    fi
    
    # Install tfsec
    if ! command_exists tfsec; then
        print_status "Installing tfsec..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            brew install tfsec
        fi
        print_success "tfsec installed"
    fi
    
    # Install Cosign
    if ! command_exists cosign; then
        print_status "Installing Cosign..."
        go install github.com/sigstore/cosign/v2/cmd/cosign@latest
        print_success "Cosign installed"
    fi
    
    # Install Vault CLI
    if ! command_exists vault; then
        print_status "Installing Vault CLI..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
            sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
            sudo apt-get update && sudo apt-get install vault
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            brew tap hashicorp/tap
            brew install hashicorp/tap/vault
        fi
        print_success "Vault CLI installed"
    fi
}

# Function to setup Python environment
setup_python_env() {
    print_status "Setting up Python environment..."
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Python dependencies installed"
    fi
}

# Function to create kind cluster configuration
create_kind_config() {
    print_status "Creating kind cluster configuration..."
    
    cat > k8s/kind-config.yaml << EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: sentinel-security
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
  - containerPort: 8080
    hostPort: 8080
    protocol: TCP
  - containerPort: 9090
    hostPort: 9090
    protocol: TCP
  - containerPort: 3000
    hostPort: 3000
    protocol: TCP
- role: worker
- role: worker
EOF
    
    print_success "Kind configuration created"
}

# Function to setup Helm repositories
setup_helm_repos() {
    print_status "Setting up Helm repositories..."
    
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo add elastic https://helm.elastic.co
    helm repo add falcosecurity https://falcosecurity.github.io/charts
    helm repo add hashicorp https://helm.releases.hashicorp.com
    helm repo add jetstack https://charts.jetstack.io
    helm repo add bitnami https://charts.bitnami.com/bitnami
    
    helm repo update
    
    print_success "Helm repositories configured"
}

# Function to create initial directory structure
create_directories() {
    print_status "Creating additional directories..."
    
    mkdir -p {logs,reports,backups}
    mkdir -p scans/{trivy,checkov,tfsec,snyk}
    mkdir -p compliance/{reports,policies}
    mkdir -p k8s/{namespaces,rbac,network-policies}
    
    print_success "Directory structure created"
}

# Main setup function
main() {
    echo
    print_status "Starting Project Sentinel setup..."
    echo
    
    check_prerequisites
    echo
    
    install_security_tools
    echo
    
    setup_python_env
    echo
    
    create_kind_config
    echo
    
    setup_helm_repos
    echo
    
    create_directories
    echo
    
    print_success "🎉 Project Sentinel setup completed successfully!"
    echo
    print_status "Next steps:"
    echo "1. Run './scripts/deploy-all.sh' to deploy the security platform"
    echo "2. Run './demos/run-demo.sh' to execute security demonstrations"
    echo "3. Visit http://localhost:3000 for Grafana dashboard"
    echo "4. Visit http://localhost:9090 for Prometheus"
    echo
    print_status "Documentation available in ./docs/"
}

# Run main function
main "$@"