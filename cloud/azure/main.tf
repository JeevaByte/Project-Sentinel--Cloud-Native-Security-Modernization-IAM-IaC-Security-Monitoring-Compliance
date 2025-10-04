# Project Sentinel - Azure AKS Implementation
# Comprehensive cloud-native security platform with Azure services integration

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
  }
}

# Configure Azure provider
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azuread" {}

# Get current Azure configuration
data "azurerm_client_config" "current" {}

# Resource Group
resource "azurerm_resource_group" "sentinel" {
  name     = "${var.cluster_name}-rg"
  location = var.azure_location
  
  tags = {
    Environment = var.environment
    Project     = "Sentinel-Security"
    ManagedBy   = "Terraform"
    Owner       = var.owner
  }
}

# Virtual Network
resource "azurerm_virtual_network" "sentinel" {
  name                = "${var.cluster_name}-vnet"
  address_space       = [var.vnet_cidr]
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  
  tags = azurerm_resource_group.sentinel.tags
}

# Subnets
resource "azurerm_subnet" "aks" {
  name                 = "${var.cluster_name}-aks-subnet"
  resource_group_name  = azurerm_resource_group.sentinel.name
  virtual_network_name = azurerm_virtual_network.sentinel.name
  address_prefixes     = [var.aks_subnet_cidr]
}

resource "azurerm_subnet" "appgw" {
  name                 = "${var.cluster_name}-appgw-subnet"
  resource_group_name  = azurerm_resource_group.sentinel.name
  virtual_network_name = azurerm_virtual_network.sentinel.name
  address_prefixes     = [var.appgw_subnet_cidr]
}

# Network Security Groups
resource "azurerm_network_security_group" "aks" {
  name                = "${var.cluster_name}-aks-nsg"
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  
  # Allow HTTPS inbound
  security_rule {
    name                       = "HTTPS"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  
  # Allow HTTP inbound for development
  security_rule {
    name                       = "HTTP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  
  tags = azurerm_resource_group.sentinel.tags
}

# Associate NSG with AKS subnet
resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

# Log Analytics Workspace for monitoring
resource "azurerm_log_analytics_workspace" "sentinel" {
  name                = "${var.cluster_name}-law"
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  
  tags = azurerm_resource_group.sentinel.tags
}

# Azure Monitor for containers solution
resource "azurerm_log_analytics_solution" "container_insights" {
  solution_name         = "ContainerInsights"
  location              = azurerm_resource_group.sentinel.location
  resource_group_name   = azurerm_resource_group.sentinel.name
  workspace_resource_id = azurerm_log_analytics_workspace.sentinel.id
  workspace_name        = azurerm_log_analytics_workspace.sentinel.name
  
  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/ContainerInsights"
  }
  
  tags = azurerm_resource_group.sentinel.tags
}

# Key Vault for secrets management
resource "azurerm_key_vault" "sentinel" {
  name                       = "${var.cluster_name}-kv-${random_string.suffix.result}"
  location                   = azurerm_resource_group.sentinel.location
  resource_group_name        = azurerm_resource_group.sentinel.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  
  # Enable RBAC for Key Vault
  enable_rbac_authorization = true
  
  # Network access restrictions
  network_acls {
    default_action = "Allow"  # Set to Deny in production
    bypass         = "AzureServices"
  }
  
  tags = azurerm_resource_group.sentinel.tags
}

# Container Registry
resource "azurerm_container_registry" "sentinel" {
  name                = "${replace(var.cluster_name, "-", "")}acr${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.sentinel.name
  location            = azurerm_resource_group.sentinel.location
  sku                 = "Premium"
  admin_enabled       = false
  
  # Enable vulnerability scanning
  quarantine_policy_enabled = true
  trust_policy {
    enabled = true
  }
  
  retention_policy {
    days    = 30
    enabled = true
  }
  
  tags = azurerm_resource_group.sentinel.tags
}

# Azure Kubernetes Service
resource "azurerm_kubernetes_cluster" "sentinel" {
  name                = var.cluster_name
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  dns_prefix          = "${var.cluster_name}-dns"
  kubernetes_version  = var.kubernetes_version
  
  # Default node pool
  default_node_pool {
    name                = "default"
    node_count          = var.node_count
    vm_size             = var.vm_size
    vnet_subnet_id      = azurerm_subnet.aks.id
    enable_auto_scaling = true
    min_count          = var.min_node_count
    max_count          = var.max_node_count
    os_disk_size_gb    = 100
    
    # Enable monitoring
    upgrade_settings {
      max_surge = "10%"
    }
    
    tags = azurerm_resource_group.sentinel.tags
  }
  
  # Service Principal or Managed Identity
  identity {
    type = "SystemAssigned"
  }
  
  # Network configuration
  network_profile {
    network_plugin    = "azure"
    load_balancer_sku = "standard"
    outbound_type     = "loadBalancer"
  }
  
  # Enable RBAC
  role_based_access_control_enabled = true
  
  # Azure AD integration
  azure_active_directory_role_based_access_control {
    managed                = true
    admin_group_object_ids = [azuread_group.aks_admins.object_id]
    azure_rbac_enabled     = true
  }
  
  # Enable monitoring
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.sentinel.id
  }
  
  # Enable auto-upgrade
  automatic_channel_upgrade = "patch"
  
  # Enable Key Vault secrets provider
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }
  
  # Enable Azure Policy
  azure_policy_enabled = true
  
  # HTTP application routing (disable in production)
  http_application_routing_enabled = false
  
  # API server access profile
  api_server_access_profile {
    vnet_integration_enabled = false
    authorized_ip_ranges     = var.authorized_ip_ranges
  }
  
  tags = azurerm_resource_group.sentinel.tags
}

# Additional node pool for security workloads
resource "azurerm_kubernetes_cluster_node_pool" "security" {
  name                  = "security"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.sentinel.id
  vm_size               = "Standard_D4s_v3"
  node_count            = 2
  vnet_subnet_id        = azurerm_subnet.aks.id
  
  enable_auto_scaling = true
  min_count          = 1
  max_count          = 5
  
  node_labels = {
    "workload-type" = "security"
  }
  
  node_taints = [
    "workload-type=security:NoSchedule"
  ]
  
  tags = azurerm_resource_group.sentinel.tags
}

# Azure AD Group for AKS admins
resource "azuread_group" "aks_admins" {
  display_name     = "${var.cluster_name}-admins"
  security_enabled = true
  description      = "AKS cluster administrators for ${var.cluster_name}"
}

# Azure Defender for Kubernetes
resource "azurerm_security_center_subscription_pricing" "defender_kubernetes" {
  tier          = "Standard"
  resource_type = "KubernetesService"
}

resource "azurerm_security_center_subscription_pricing" "defender_container_registry" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}

# Azure Sentinel (SIEM)
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id = azurerm_log_analytics_workspace.sentinel.id
}

# Storage Account for diagnostics and logs
resource "azurerm_storage_account" "sentinel" {
  name                     = "${replace(var.cluster_name, "-", "")}st${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.sentinel.name
  location                 = azurerm_resource_group.sentinel.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  # Enable blob encryption
  blob_properties {
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
  
  # Network access restrictions
  network_rules {
    default_action = "Allow"  # Set to Deny in production
    bypass         = ["AzureServices"]
  }
  
  tags = azurerm_resource_group.sentinel.tags
}

# Application Gateway for ingress
resource "azurerm_public_ip" "appgw" {
  name                = "${var.cluster_name}-appgw-pip"
  resource_group_name = azurerm_resource_group.sentinel.name
  location            = azurerm_resource_group.sentinel.location
  allocation_method   = "Static"
  sku                 = "Standard"
  
  tags = azurerm_resource_group.sentinel.tags
}

resource "azurerm_application_gateway" "sentinel" {
  name                = "${var.cluster_name}-appgw"
  resource_group_name = azurerm_resource_group.sentinel.name
  location            = azurerm_resource_group.sentinel.location
  
  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }
  
  gateway_ip_configuration {
    name      = "gateway-ip-configuration"
    subnet_id = azurerm_subnet.appgw.id
  }
  
  frontend_port {
    name = "frontend-port-80"
    port = 80
  }
  
  frontend_port {
    name = "frontend-port-443"
    port = 443
  }
  
  frontend_ip_configuration {
    name                 = "frontend-ip-configuration"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }
  
  backend_address_pool {
    name = "backend-pool"
  }
  
  backend_http_settings {
    name                  = "backend-http-settings"
    cookie_based_affinity = "Disabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 60
  }
  
  http_listener {
    name                           = "http-listener"
    frontend_ip_configuration_name = "frontend-ip-configuration"
    frontend_port_name             = "frontend-port-80"
    protocol                       = "Http"
  }
  
  request_routing_rule {
    name                       = "routing-rule"
    rule_type                  = "Basic"
    http_listener_name         = "http-listener"
    backend_address_pool_name  = "backend-pool"
    backend_http_settings_name = "backend-http-settings"
  }
  
  # Enable WAF
  waf_configuration {
    enabled          = true
    firewall_mode    = "Prevention"
    rule_set_type    = "OWASP"
    rule_set_version = "3.2"
  }
  
  tags = azurerm_resource_group.sentinel.tags
}

# Azure Policy assignments for security
resource "azurerm_resource_group_policy_assignment" "kubernetes_cluster_pod_security_baseline" {
  name                 = "kubernetes-pod-security-baseline"
  resource_group_id    = azurerm_resource_group.sentinel.id
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/a8640138-9b0a-4a28-b8cb-1666c838647d"
  
  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Random string for unique resource naming
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Role assignments
resource "azurerm_role_assignment" "aks_acr_pull" {
  principal_id                     = azurerm_kubernetes_cluster.sentinel.kubelet_identity[0].object_id
  role_definition_name             = "AcrPull"
  scope                           = azurerm_container_registry.sentinel.id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "aks_network_contributor" {
  principal_id         = azurerm_kubernetes_cluster.sentinel.identity[0].principal_id
  role_definition_name = "Network Contributor"
  scope               = azurerm_virtual_network.sentinel.id
}

# Key Vault access for AKS
resource "azurerm_role_assignment" "aks_key_vault_secrets_user" {
  principal_id         = azurerm_kubernetes_cluster.sentinel.key_vault_secrets_provider[0].secret_identity[0].object_id
  role_definition_name = "Key Vault Secrets User"
  scope               = azurerm_key_vault.sentinel.id
}