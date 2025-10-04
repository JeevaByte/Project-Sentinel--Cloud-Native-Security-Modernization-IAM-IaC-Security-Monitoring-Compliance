# Azure AKS Variables

variable "cluster_name" {
  description = "Name of the AKS cluster"
  type        = string
  default     = "sentinel-security"
}

variable "azure_location" {
  description = "Azure region for resources"
  type        = string
  default     = "West US 2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "owner" {
  description = "Owner of the resources"
  type        = string
  default     = "security-team"
}

variable "kubernetes_version" {
  description = "Kubernetes version for AKS cluster"
  type        = string
  default     = "1.28.3"
}

# Network configuration
variable "vnet_cidr" {
  description = "CIDR block for VNet"
  type        = string
  default     = "10.0.0.0/16"
}

variable "aks_subnet_cidr" {
  description = "CIDR block for AKS subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "appgw_subnet_cidr" {
  description = "CIDR block for Application Gateway subnet"
  type        = string
  default     = "10.0.2.0/24"
}

# Node pool configuration
variable "node_count" {
  description = "Initial number of nodes in the default node pool"
  type        = number
  default     = 3
}

variable "min_node_count" {
  description = "Minimum number of nodes for autoscaling"
  type        = number
  default     = 1
}

variable "max_node_count" {
  description = "Maximum number of nodes for autoscaling"
  type        = number
  default     = 10
}

variable "vm_size" {
  description = "VM size for AKS nodes"
  type        = string
  default     = "Standard_D2s_v3"
}

# Security configuration
variable "authorized_ip_ranges" {
  description = "IP ranges allowed to access the Kubernetes API server"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Restrict this in production
}

variable "enable_azure_policy" {
  description = "Enable Azure Policy add-on"
  type        = bool
  default     = true
}

variable "enable_oms_agent" {
  description = "Enable OMS agent for monitoring"
  type        = bool
  default     = true
}

variable "enable_key_vault_secrets_provider" {
  description = "Enable Key Vault secrets provider"
  type        = bool
  default     = true
}

# Monitoring and logging
variable "log_retention_days" {
  description = "Log Analytics workspace retention in days"
  type        = number
  default     = 30
}

variable "enable_container_insights" {
  description = "Enable Container Insights"
  type        = bool
  default     = true
}

# Azure Defender
variable "enable_defender_kubernetes" {
  description = "Enable Azure Defender for Kubernetes"
  type        = bool
  default     = true
}

variable "enable_defender_container_registry" {
  description = "Enable Azure Defender for Container Registry"
  type        = bool
  default     = true
}

# Storage configuration
variable "storage_account_tier" {
  description = "Storage account tier"
  type        = string
  default     = "Standard"
}

variable "storage_replication_type" {
  description = "Storage account replication type"
  type        = string
  default     = "LRS"
}

# Application Gateway configuration
variable "appgw_sku_name" {
  description = "Application Gateway SKU name"
  type        = string
  default     = "Standard_v2"
}

variable "appgw_sku_tier" {
  description = "Application Gateway SKU tier"
  type        = string
  default     = "Standard_v2"
}

variable "appgw_sku_capacity" {
  description = "Application Gateway SKU capacity"
  type        = number
  default     = 2
}

variable "enable_waf" {
  description = "Enable Web Application Firewall on Application Gateway"
  type        = bool
  default     = true
}

# Azure AD configuration
variable "azure_ad_admin_group_object_ids" {
  description = "Object IDs of Azure AD groups for AKS administrators"
  type        = list(string)
  default     = []
}

# Backup and disaster recovery
variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
}

variable "enable_backup" {
  description = "Enable backup for AKS persistent volumes"
  type        = bool
  default     = true
}

# Cost optimization
variable "enable_cluster_autoscaler" {
  description = "Enable cluster autoscaler"
  type        = bool
  default     = true
}

variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = false
}

# Compliance and governance
variable "enable_azure_sentinel" {
  description = "Enable Azure Sentinel"
  type        = bool
  default     = true
}

variable "enable_azure_security_center" {
  description = "Enable Azure Security Center"
  type        = bool
  default     = true
}

# Application configuration
variable "application_names" {
  description = "List of application names for container images"
  type        = list(string)
  default     = ["demo-web", "postgres", "vault", "falco", "prometheus", "grafana"]
}

# Tags
variable "additional_tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Network security
variable "enable_network_policy" {
  description = "Enable network policy (Calico/Azure)"
  type        = string
  default     = "azure"
  validation {
    condition     = contains(["azure", "calico", "none"], var.enable_network_policy)
    error_message = "Network policy must be 'azure', 'calico', or 'none'."
  }
}

variable "enable_private_cluster" {
  description = "Enable private cluster (API server with private IP)"
  type        = bool
  default     = false
}

# Container registry configuration
variable "acr_sku" {
  description = "Container Registry SKU"
  type        = string
  default     = "Premium"
  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.acr_sku)
    error_message = "ACR SKU must be Basic, Standard, or Premium."
  }
}

variable "enable_acr_vulnerability_scanning" {
  description = "Enable vulnerability scanning for Container Registry"
  type        = bool
  default     = true
}