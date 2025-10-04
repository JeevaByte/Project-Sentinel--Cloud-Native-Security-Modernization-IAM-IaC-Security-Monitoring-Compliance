#!/bin/bash

# Vault Configuration Script for Sentinel Project
# This script configures HashiCorp Vault for dynamic database credentials

set -e

# Colors for output
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

# Wait for Vault to be ready
wait_for_vault() {
    print_status "Waiting for Vault to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if kubectl exec -n vault vault-0 -- vault status > /dev/null 2>&1; then
            print_success "Vault is ready"
            return 0
        fi
        
        print_status "Attempt $attempt/$max_attempts: Vault not ready yet..."
        sleep 10
        ((attempt++))
    done
    
    echo "Vault failed to become ready after $max_attempts attempts"
    exit 1
}

# Configure Vault authentication
configure_vault_auth() {
    print_status "Configuring Vault authentication..."
    
    # Set vault address
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="myroot"
    
    # Port forward to access Vault
    kubectl port-forward -n vault vault-0 8200:8200 &
    PORT_FORWARD_PID=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Enable Kubernetes auth method
    vault auth enable kubernetes
    
    # Configure Kubernetes auth
    vault write auth/kubernetes/config \
        token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
        kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" \
        kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    
    print_success "Vault authentication configured"
}

# Configure database secrets engine
configure_database_engine() {
    print_status "Configuring database secrets engine..."
    
    # Enable database secrets engine
    vault secrets enable database
    
    # Configure PostgreSQL connection
    vault write database/config/postgresql \
        plugin_name=postgresql-database-plugin \
        connection_url="postgresql://{{username}}:{{password}}@postgres.sentinel-apps.svc.cluster.local:5432/demo?sslmode=disable" \
        allowed_roles="demo-role" \
        username="user" \
        password="password"
    
    # Create role for dynamic credentials
    vault write database/roles/demo-role \
        db_name=postgresql \
        creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
        default_ttl="1h" \
        max_ttl="24h"
    
    print_success "Database secrets engine configured"
}

# Configure KV secrets engine
configure_kv_engine() {
    print_status "Configuring KV secrets engine..."
    
    # Enable KV v2 secrets engine
    vault secrets enable -path=secret kv-v2
    
    # Store application secrets
    vault kv put secret/demo-app \
        jwt_secret="$(openssl rand -hex 32)" \
        api_key="$(openssl rand -hex 16)" \
        encryption_key="$(openssl rand -hex 32)"
    
    # Store database admin credentials
    vault kv put secret/database \
        admin_username="postgres" \
        admin_password="$(openssl rand -alphanumeric 32)" \
        connection_string="postgresql://postgres:password@postgres.sentinel-apps.svc.cluster.local:5432/demo"
    
    print_success "KV secrets engine configured"
}

# Configure policies
configure_policies() {
    print_status "Configuring Vault policies..."
    
    # Create policy for demo application
    vault policy write demo-app-policy - <<EOF
# Read application secrets
path "secret/data/demo-app" {
  capabilities = ["read"]
}

# Generate database credentials
path "database/creds/demo-role" {
  capabilities = ["read"]
}

# Renew credentials
path "database/renew" {
  capabilities = ["update"]
}
EOF

    # Create policy for database access
    vault policy write database-admin-policy - <<EOF
# Full access to database secrets
path "secret/data/database" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Manage database configurations
path "database/config/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Manage database roles
path "database/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

    print_success "Vault policies configured"
}

# Configure Kubernetes integration
configure_k8s_integration() {
    print_status "Configuring Kubernetes integration..."
    
    # Create role for demo application
    vault write auth/kubernetes/role/demo-app \
        bound_service_account_names=demo-web-service-sa \
        bound_service_account_namespaces=sentinel-apps \
        policies=demo-app-policy \
        ttl=24h
    
    # Create role for database admin
    vault write auth/kubernetes/role/database-admin \
        bound_service_account_names=postgres-admin-sa \
        bound_service_account_namespaces=sentinel-apps \
        policies=database-admin-policy \
        ttl=1h
    
    print_success "Kubernetes integration configured"
}

# Test Vault configuration
test_vault_config() {
    print_status "Testing Vault configuration..."
    
    # Test database credential generation
    print_status "Generating test database credentials..."
    vault read database/creds/demo-role
    
    # Test secret retrieval
    print_status "Retrieving application secrets..."
    vault kv get secret/demo-app
    
    # Test policy
    print_status "Testing policy permissions..."
    vault policy read demo-app-policy
    
    print_success "Vault configuration test completed"
}

# Create Vault agent configuration
create_vault_agent_config() {
    print_status "Creating Vault agent configuration..."
    
    cat > /tmp/vault-agent-config.hcl << 'EOF'
# Vault agent configuration for demo application
vault {
  address = "http://vault.vault.svc.cluster.local:8200"
}

auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      role = "demo-app"
    }
  }

  sink "file" {
    config = {
      path = "/vault/secrets/token"
    }
  }
}

template {
  source      = "/vault/config/db-config.tpl"
  destination = "/vault/secrets/db-config.json"
  perms       = 0644
}

template {
  source      = "/vault/config/app-config.tpl"
  destination = "/vault/secrets/app-config.json"
  perms       = 0644
}
EOF

    # Create database configuration template
    cat > /tmp/db-config.tpl << 'EOF'
{
  {{- with secret "database/creds/demo-role" }}
  "database": {
    "host": "postgres.sentinel-apps.svc.cluster.local",
    "port": 5432,
    "database": "demo",
    "username": "{{ .Data.username }}",
    "password": "{{ .Data.password }}",
    "ssl_mode": "require"
  }
  {{- end }}
}
EOF

    # Create application configuration template
    cat > /tmp/app-config.tpl << 'EOF'
{
  {{- with secret "secret/data/demo-app" }}
  "application": {
    "jwt_secret": "{{ .Data.data.jwt_secret }}",
    "api_key": "{{ .Data.data.api_key }}",
    "encryption_key": "{{ .Data.data.encryption_key }}"
  }
  {{- end }}
}
EOF

    print_success "Vault agent configuration created"
}

# Main configuration function
main() {
    echo
    print_status "🔐 Configuring HashiCorp Vault for Project Sentinel..."
    echo
    
    wait_for_vault
    echo
    
    configure_vault_auth
    echo
    
    configure_database_engine
    echo
    
    configure_kv_engine
    echo
    
    configure_policies
    echo
    
    configure_k8s_integration
    echo
    
    create_vault_agent_config
    echo
    
    test_vault_config
    echo
    
    # Cleanup port forward
    if [ ! -z "$PORT_FORWARD_PID" ]; then
        kill $PORT_FORWARD_PID 2>/dev/null || true
    fi
    
    print_success "🎉 Vault configuration completed successfully!"
    echo
    print_status "Next steps:"
    echo "1. Deploy applications with Vault integration"
    echo "2. Test dynamic credential generation"
    echo "3. Monitor secret rotations"
    echo
    print_status "Useful commands:"
    echo "kubectl exec -n vault vault-0 -- vault read database/creds/demo-role"
    echo "kubectl exec -n vault vault-0 -- vault kv get secret/demo-app"
}

# Run main function
main "$@"