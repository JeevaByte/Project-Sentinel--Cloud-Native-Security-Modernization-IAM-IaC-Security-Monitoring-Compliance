# AWS EKS Variables

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-west-2"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "sentinel-security"
}

variable "kubernetes_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.28"
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

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnets" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnets" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "application_names" {
  description = "List of application names for ECR repositories"
  type        = list(string)
  default     = ["demo-web", "postgres", "vault", "falco", "prometheus", "grafana"]
}

variable "aws_auth_users" {
  description = "Additional IAM users to add to the aws-auth configmap"
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
  default = []
}

# Security configurations
variable "enable_guardduty" {
  description = "Enable AWS GuardDuty"
  type        = bool
  default     = true
}

variable "enable_config" {
  description = "Enable AWS Config"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub"
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

# Monitoring and alerting
variable "enable_container_insights" {
  description = "Enable CloudWatch Container Insights"
  type        = bool
  default     = true
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring for RDS and other services"
  type        = bool
  default     = true
}

# Compliance and governance
variable "enable_cost_allocation_tags" {
  description = "Enable cost allocation tags"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
}

# Network security
variable "restrict_cluster_endpoint_public_access" {
  description = "Restrict public access to cluster endpoint"
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of CIDR blocks that can access the cluster endpoint publicly"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_irsa" {
  description = "Enable IAM Roles for Service Accounts"
  type        = bool
  default     = true
}

# Scaling configurations
variable "cluster_autoscaler_enabled" {
  description = "Enable cluster autoscaler"
  type        = bool
  default     = true
}

variable "vertical_pod_autoscaler_enabled" {
  description = "Enable vertical pod autoscaler"
  type        = bool
  default     = true
}

# Add-on versions
variable "addon_versions" {
  description = "EKS addon versions"
  type = object({
    vpc_cni            = string
    coredns            = string
    kube_proxy         = string
    ebs_csi_driver     = string
    aws_load_balancer_controller = string
  })
  default = {
    vpc_cni            = "v1.14.1-eksbuild.1"
    coredns            = "v1.10.1-eksbuild.1"
    kube_proxy         = "v1.28.1-eksbuild.1"
    ebs_csi_driver     = "v1.22.0-eksbuild.1"
    aws_load_balancer_controller = "v2.6.0"
  }
}