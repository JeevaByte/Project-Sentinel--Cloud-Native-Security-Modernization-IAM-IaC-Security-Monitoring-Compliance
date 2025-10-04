# Project Sentinel - Terraform Variables

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-west-2"
  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be in the format 'us-west-2'."
  }
}

variable "azure_location" {
  description = "Azure region for resources"
  type        = string
  default     = "West US 2"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "demo"
  validation {
    condition     = contains(["dev", "staging", "prod", "demo"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod, demo."
  }
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "sentinel"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.project_name))
    error_message = "Project name must start with a letter, contain only lowercase letters, numbers, and hyphens, and end with a letter or number."
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access resources"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # INTENTIONALLY INSECURE for demo
}

variable "enable_monitoring" {
  description = "Enable detailed monitoring"
  type        = bool
  default     = false  # Should be true in production
}

variable "enable_encryption" {
  description = "Enable encryption for storage resources"
  type        = bool
  default     = false  # INTENTIONALLY DISABLED for demo
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 0  # INTENTIONALLY DISABLED for demo
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "sentinel"
    Environment = "demo"
    Owner       = "security-team"
    # Missing security-related tags intentionally
  }
}