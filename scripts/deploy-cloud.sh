#!/bin/bash
# Project Sentinel - Cloud Deployment Automation Script
# Supports AWS EKS and Azure AKS deployments with full security stack

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
CLOUD_PROVIDER=""
CLUSTER_NAME="sentinel-security"
ENVIRONMENT="dev"
REGION=""
RESOURCE_GROUP=""
AUTO_APPROVE=false
SKIP_APPS=false

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                    PROJECT SENTINEL                         ║
║              Cloud Deployment Automation                    ║
║                                                              ║
║     Enterprise-Grade Security Platform for the Cloud        ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy Project Sentinel to cloud providers with comprehensive security stack.

OPTIONS:
    -p, --provider PROVIDER    Cloud provider: aws, azure (required)
    -n, --name NAME           Cluster name (default: sentinel-security)
    -e, --environment ENV     Environment: dev, staging, prod (default: dev)
    -r, --region REGION       Cloud region (required)
    -g, --resource-group RG   Azure resource group name
    -y, --yes                 Auto-approve Terraform apply
    --skip-apps              Skip application deployment
    -h, --help               Show this help message

EXAMPLES:
    # Deploy to AWS EKS
    $0 --provider aws --region us-west-2 --name sentinel-aws

    # Deploy to Azure AKS
    $0 --provider azure --region "West US 2" --name sentinel-azure

    # Production deployment with auto-approve
    $0 --provider aws --region us-west-2 --environment prod --yes

PREREQUISITES:
    - Terraform >= 1.0
    - kubectl
    - helm
    - Cloud provider CLI (aws-cli or azure-cli)
    - Configured cloud credentials

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--provider)
            CLOUD_PROVIDER="$2"
            shift 2
            ;;
        -n|--name)
            CLUSTER_NAME="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -g|--resource-group)
            RESOURCE_GROUP="$2"
            shift 2
            ;;
        -y|--yes)
            AUTO_APPROVE=true
            shift
            ;;
        --skip-apps)
            SKIP_APPS=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            show_help
            exit 1
            ;;
    esac
done

# Validation
if [[ -z "$CLOUD_PROVIDER" ]]; then
    echo -e "${RED}Error: Cloud provider is required${NC}"
    show_help
    exit 1
fi

if [[ "$CLOUD_PROVIDER" != "aws" && "$CLOUD_PROVIDER" != "azure" ]]; then
    echo -e "${RED}Error: Supported providers are 'aws' and 'azure'${NC}"
    exit 1
fi

if [[ -z "$REGION" ]]; then
    echo -e "${RED}Error: Region is required${NC}"
    show_help
    exit 1
fi

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"
    
    local missing_tools=()
    
    # Check common tools
    for tool in terraform kubectl helm; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=($tool)
        fi
    done
    
    # Check cloud-specific tools
    case $CLOUD_PROVIDER in
        aws)
            if ! command -v aws &> /dev/null; then
                missing_tools+=(aws-cli)
            fi
            ;;
        azure)
            if ! command -v az &> /dev/null; then
                missing_tools+=(azure-cli)
            fi
            ;;
    esac
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Missing required tools: ${missing_tools[*]}${NC}"
        echo "Please install missing tools before continuing."
        exit 1
    fi
    
    echo -e "${GREEN}✅ All prerequisites satisfied${NC}"
}

# Verify cloud credentials
verify_credentials() {
    echo -e "${BLUE}🔐 Verifying cloud credentials...${NC}"
    
    case $CLOUD_PROVIDER in
        aws)
            if ! aws sts get-caller-identity &> /dev/null; then
                echo -e "${RED}❌ AWS credentials not configured${NC}"
                echo "Run 'aws configure' to set up credentials"
                exit 1
            fi
            echo -e "${GREEN}✅ AWS credentials verified${NC}"
            ;;
        azure)
            if ! az account show &> /dev/null; then
                echo -e "${RED}❌ Azure credentials not configured${NC}"
                echo "Run 'az login' to authenticate"
                exit 1
            fi
            echo -e "${GREEN}✅ Azure credentials verified${NC}"
            ;;
    esac
}

# Deploy infrastructure
deploy_infrastructure() {
    echo -e "${BLUE}🏗️ Deploying infrastructure to $CLOUD_PROVIDER...${NC}"
    
    local cloud_dir="$PROJECT_ROOT/cloud/$CLOUD_PROVIDER"
    
    if [[ ! -d "$cloud_dir" ]]; then
        echo -e "${RED}❌ Cloud provider directory not found: $cloud_dir${NC}"
        exit 1
    fi
    
    cd "$cloud_dir"
    
    # Initialize Terraform
    echo -e "${YELLOW}Initializing Terraform...${NC}"
    terraform init
    
    # Create terraform.tfvars
    cat > terraform.tfvars << EOF
cluster_name = "$CLUSTER_NAME"
environment = "$ENVIRONMENT"
EOF
    
    case $CLOUD_PROVIDER in
        aws)
            echo "aws_region = \"$REGION\"" >> terraform.tfvars
            ;;
        azure)
            echo "azure_location = \"$REGION\"" >> terraform.tfvars
            if [[ -n "$RESOURCE_GROUP" ]]; then
                echo "resource_group_name = \"$RESOURCE_GROUP\"" >> terraform.tfvars
            fi
            ;;
    esac
    
    # Plan deployment
    echo -e "${YELLOW}Planning deployment...${NC}"
    terraform plan -out=tfplan
    
    # Apply deployment
    if [[ "$AUTO_APPROVE" == "true" ]]; then
        echo -e "${YELLOW}Applying deployment (auto-approved)...${NC}"
        terraform apply -auto-approve tfplan
    else
        echo -e "${YELLOW}Applying deployment...${NC}"
        terraform apply tfplan
    fi
    
    echo -e "${GREEN}✅ Infrastructure deployment completed${NC}"
}

# Configure kubectl
configure_kubectl() {
    echo -e "${BLUE}⚙️ Configuring kubectl...${NC}"
    
    case $CLOUD_PROVIDER in
        aws)
            aws eks update-kubeconfig --region "$REGION" --name "$CLUSTER_NAME"
            ;;
        azure)
            local rg_name="${CLUSTER_NAME}-rg"
            if [[ -n "$RESOURCE_GROUP" ]]; then
                rg_name="$RESOURCE_GROUP"
            fi
            az aks get-credentials --resource-group "$rg_name" --name "$CLUSTER_NAME"
            ;;
    esac
    
    # Verify connection
    if kubectl get nodes &> /dev/null; then
        echo -e "${GREEN}✅ kubectl configured successfully${NC}"
        kubectl get nodes
    else
        echo -e "${RED}❌ Failed to configure kubectl${NC}"
        exit 1
    fi
}

# Deploy applications
deploy_applications() {
    if [[ "$SKIP_APPS" == "true" ]]; then
        echo -e "${YELLOW}⏭️ Skipping application deployment${NC}"
        return
    fi
    
    echo -e "${BLUE}🚀 Deploying applications and security stack...${NC}"
    
    cd "$PROJECT_ROOT"
    
    # Deploy security namespace and RBAC
    kubectl apply -f k8s/security/
    
    # Deploy Falco for runtime security
    echo -e "${YELLOW}Installing Falco...${NC}"
    helm repo add falcosecurity https://falcosecurity.github.io/charts
    helm repo update
    
    helm upgrade --install falco falcosecurity/falco \
        --namespace falco-system \
        --create-namespace \
        --set falco.grpc.enabled=true \
        --set falco.grpcOutput.enabled=true \
        --set falco.fileOutput.enabled=true \
        --set falco.httpOutput.enabled=true \
        --wait
    
    # Deploy monitoring stack
    echo -e "${YELLOW}Installing monitoring stack...${NC}"
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo update
    
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace monitoring \
        --create-namespace \
        --set grafana.adminPassword=admin \
        --set prometheus.prometheusSpec.retention=30d \
        --wait
    
    # Deploy demo applications
    echo -e "${YELLOW}Deploying demo applications...${NC}"
    kubectl apply -f k8s/apps/
    
    # Wait for deployments to be ready
    echo -e "${YELLOW}Waiting for deployments to be ready...${NC}"
    kubectl wait --for=condition=available --timeout=300s deployment --all -n sentinel-apps
    
    echo -e "${GREEN}✅ Applications deployed successfully${NC}"
}

# Show deployment summary
show_summary() {
    echo -e "${CYAN}📋 Deployment Summary${NC}"
    echo -e "${CYAN}===================${NC}"
    echo
    
    echo -e "${GREEN}✅ Infrastructure:${NC} $CLOUD_PROVIDER cluster '$CLUSTER_NAME'"
    echo -e "${GREEN}✅ Region:${NC} $REGION"
    echo -e "${GREEN}✅ Environment:${NC} $ENVIRONMENT"
    echo
    
    echo -e "${BLUE}🔗 Access Information:${NC}"
    
    # Get ingress/load balancer information
    if kubectl get svc -n monitoring prometheus-grafana &> /dev/null; then
        echo "• Grafana: kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80"
        echo "  Then access: http://localhost:3000 (admin/admin)"
    fi
    
    if kubectl get svc -n monitoring prometheus-server &> /dev/null; then
        echo "• Prometheus: kubectl port-forward -n monitoring svc/prometheus-server 9090:80"
        echo "  Then access: http://localhost:9090"
    fi
    
    if kubectl get svc -n sentinel-apps demo-web-service &> /dev/null; then
        echo "• Demo App: kubectl port-forward -n sentinel-apps svc/demo-web-service 8080:80"
        echo "  Then access: http://localhost:8080"
    fi
    
    echo
    echo -e "${BLUE}🛡️ Security Features Enabled:${NC}"
    
    case $CLOUD_PROVIDER in
        aws)
            echo "• GuardDuty threat detection"
            echo "• Security Hub centralized findings"
            echo "• Config compliance monitoring"
            echo "• ECR vulnerability scanning"
            echo "• VPC Flow Logs"
            ;;
        azure)
            echo "• Azure Defender for Kubernetes"
            echo "• Azure Sentinel SIEM"
            echo "• Azure Policy compliance"
            echo "• ACR vulnerability scanning"
            echo "• Azure Monitor integration"
            ;;
    esac
    
    echo "• Falco runtime security monitoring"
    echo "• Prometheus metrics collection"
    echo "• Grafana security dashboards"
    echo
    
    echo -e "${YELLOW}📝 Next Steps:${NC}"
    echo "1. Access monitoring dashboards using port-forward commands above"
    echo "2. Run security simulations: ./scripts/demo-security-monitoring.sh"
    echo "3. Generate compliance reports: python scripts/compliance-engine.py"
    echo "4. Review cloud-specific security findings in provider console"
    echo "5. Configure alerting and notifications for production use"
    echo
    
    echo -e "${GREEN}🎉 Project Sentinel cloud deployment completed successfully!${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}Starting Project Sentinel cloud deployment...${NC}"
    echo -e "${BLUE}Provider: $CLOUD_PROVIDER | Cluster: $CLUSTER_NAME | Region: $REGION${NC}"
    echo
    
    check_prerequisites
    verify_credentials
    deploy_infrastructure
    configure_kubectl
    deploy_applications
    show_summary
}

# Handle script interruption
trap 'echo -e "\n${YELLOW}Deployment interrupted by user${NC}"; exit 1' INT

# Run main function
main

echo -e "${GREEN}Deployment completed! 🚀${NC}"