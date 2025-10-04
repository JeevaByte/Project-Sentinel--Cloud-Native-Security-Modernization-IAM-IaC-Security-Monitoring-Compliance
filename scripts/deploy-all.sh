#!/bin/bash

# Project Sentinel - Deploy All Components
# This script deploys the complete security stack

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to wait for pods to be ready
wait_for_pods() {
    local namespace=$1
    local app_label=$2
    local timeout=${3:-300}
    
    print_status "Waiting for pods in namespace $namespace with label $app_label to be ready..."
    kubectl wait --for=condition=ready pod -l $app_label -n $namespace --timeout=${timeout}s
}

# Function to create kind cluster
create_cluster() {
    print_status "Creating kind cluster 'sentinel-security'..."
    
    if kind get clusters | grep -q "sentinel-security"; then
        print_warning "Cluster 'sentinel-security' already exists. Deleting..."
        kind delete cluster --name sentinel-security
    fi
    
    kind create cluster --config k8s/kind-config.yaml --name sentinel-security
    print_success "Kind cluster created"
    
    # Set context
    kubectl cluster-info --context kind-sentinel-security
}

# Function to create namespaces
create_namespaces() {
    print_status "Creating namespaces..."
    
    kubectl apply -f - << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: sentinel-apps
  labels:
    name: sentinel-apps
    security-policy: restricted
---
apiVersion: v1
kind: Namespace
metadata:
  name: sentinel-security
  labels:
    name: sentinel-security
    security-policy: privileged
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels:
    name: monitoring
    security-policy: monitoring
---
apiVersion: v1
kind: Namespace
metadata:
  name: vault
  labels:
    name: vault
    security-policy: vault
---
apiVersion: v1
kind: Namespace
metadata:
  name: keycloak
  labels:
    name: keycloak
    security-policy: identity
EOF
    
    print_success "Namespaces created"
}

# Function to deploy Vault
deploy_vault() {
    print_status "Deploying HashiCorp Vault..."
    
    helm install vault hashicorp/vault \
        --namespace vault \
        --set "server.dev.enabled=true" \
        --set "server.dev.devRootToken=myroot" \
        --set "injector.enabled=false" \
        --wait
    
    print_success "Vault deployed"
}

# Function to deploy Keycloak
deploy_keycloak() {
    print_status "Deploying Keycloak..."
    
    helm install keycloak bitnami/keycloak \
        --namespace keycloak \
        --set auth.adminUser=admin \
        --set auth.adminPassword=admin123 \
        --set httpRelativePath="/auth/" \
        --wait
    
    print_success "Keycloak deployed"
}

# Function to deploy monitoring stack
deploy_monitoring() {
    print_status "Deploying monitoring stack..."
    
    # Deploy Prometheus
    helm install prometheus prometheus-community/kube-prometheus-stack \
        --namespace monitoring \
        --set grafana.adminPassword=admin123 \
        --set grafana.service.type=NodePort \
        --set grafana.service.nodePort=30000 \
        --set prometheus.service.type=NodePort \
        --set prometheus.service.nodePort=30001 \
        --wait
    
    print_success "Prometheus and Grafana deployed"
    
    # Deploy Loki
    helm install loki grafana/loki-stack \
        --namespace monitoring \
        --set grafana.enabled=false \
        --wait
    
    print_success "Loki deployed"
}

# Function to deploy Falco
deploy_falco() {
    print_status "Deploying Falco for runtime security..."
    
    helm install falco falcosecurity/falco \
        --namespace sentinel-security \
        --set falco.grpc.enabled=true \
        --set falco.grpcOutput.enabled=true \
        --set falco.jsonOutput=true \
        --set falco.logLevel=info \
        --wait
    
    print_success "Falco deployed"
}

# Function to deploy OPA Gatekeeper
deploy_gatekeeper() {
    print_status "Deploying OPA Gatekeeper..."
    
    kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml
    
    # Wait for gatekeeper to be ready
    kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=300s
    
    print_success "OPA Gatekeeper deployed"
}

# Function to deploy demo applications
deploy_demo_apps() {
    print_status "Deploying demo applications..."
    
    # Deploy PostgreSQL
    kubectl apply -f - << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: sentinel-apps
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:13
        env:
        - name: POSTGRES_DB
          value: demo
        - name: POSTGRES_USER
          value: user
        - name: POSTGRES_PASSWORD
          value: password
        ports:
        - containerPort: 5432
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: sentinel-apps
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
EOF
    
    # Deploy demo web service
    kubectl apply -f - << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-web-service
  namespace: sentinel-apps
spec:
  replicas: 2
  selector:
    matchLabels:
      app: demo-web-service
  template:
    metadata:
      labels:
        app: demo-web-service
    spec:
      containers:
      - name: web-service
        image: nginx:latest
        ports:
        - containerPort: 80
        env:
        - name: DB_HOST
          value: postgres
        - name: DB_USER
          value: user
        - name: DB_PASSWORD
          value: password
---
apiVersion: v1
kind: Service
metadata:
  name: demo-web-service
  namespace: sentinel-apps
spec:
  selector:
    app: demo-web-service
  ports:
  - port: 80
    targetPort: 80
  type: NodePort
EOF
    
    print_success "Demo applications deployed"
}

# Function to setup network policies
setup_network_policies() {
    print_status "Setting up network policies..."
    
    kubectl apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: sentinel-apps
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-to-db
  namespace: sentinel-apps
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: demo-web-service
    ports:
    - protocol: TCP
      port: 5432
EOF
    
    print_success "Network policies applied"
}

# Function to deploy security policies
deploy_security_policies() {
    print_status "Deploying security policies..."
    
    # Create constraint template for required labels
    kubectl apply -f - << EOF
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        type: object
        properties:
          labels:
            type: array
            items:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        
        violation[{"msg": msg}] {
          required := input.parameters.labels
          provided := input.review.object.metadata.labels
          missing := required[_]
          not provided[missing]
          msg := sprintf("Missing required label: %v", [missing])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: must-have-security-label
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
  parameters:
    labels: ["security-policy"]
EOF
    
    print_success "Security policies deployed"
}

# Function to display access information
display_access_info() {
    print_success "🎉 Project Sentinel deployment completed!"
    echo
    print_status "Access Information:"
    echo "==================="
    echo
    echo "Grafana Dashboard:"
    echo "  URL: http://localhost:30000"
    echo "  Username: admin"
    echo "  Password: admin123"
    echo
    echo "Prometheus:"
    echo "  URL: http://localhost:30001"
    echo
    echo "Vault:"
    echo "  Pod: kubectl exec -it vault-0 -n vault -- vault status"
    echo "  Root Token: myroot"
    echo
    echo "Keycloak:"
    echo "  URL: kubectl port-forward svc/keycloak -n keycloak 8080:80"
    echo "  Username: admin"
    echo "  Password: admin123"
    echo
    print_status "Useful Commands:"
    echo "================"
    echo "View all pods: kubectl get pods -A"
    echo "View Falco logs: kubectl logs -f -n sentinel-security -l app.kubernetes.io/name=falco"
    echo "Port forward Grafana: kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80"
    echo "Port forward Prometheus: kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090"
}

# Main deployment function
main() {
    echo
    print_status "🛡️  Starting Project Sentinel deployment..."
    echo
    
    create_cluster
    echo
    
    create_namespaces
    echo
    
    deploy_vault
    echo
    
    deploy_keycloak
    echo
    
    deploy_monitoring
    echo
    
    deploy_falco
    echo
    
    deploy_gatekeeper
    echo
    
    deploy_demo_apps
    echo
    
    setup_network_policies
    echo
    
    deploy_security_policies
    echo
    
    display_access_info
}

# Run main function
main "$@"