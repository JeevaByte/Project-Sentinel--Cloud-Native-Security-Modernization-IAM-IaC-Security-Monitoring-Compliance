# Project Sentinel - Terraform Infrastructure
# This file contains intentional security misconfigurations for demonstration purposes

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# AWS Provider Configuration
provider "aws" {
  region = var.aws_region
}

# Azure Provider Configuration
provider "azurerm" {
  features {}
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "demo"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "sentinel"
}

# INTENTIONAL MISCONFIGURATION: S3 bucket with public read access
resource "aws_s3_bucket" "demo_bucket" {
  bucket = "${var.project_name}-${var.environment}-bucket-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "Demo Bucket"
    Environment = var.environment
    # Missing security-related tags
  }
}

# INTENTIONAL MISCONFIGURATION: Public read ACL
resource "aws_s3_bucket_public_access_block" "demo_bucket_pab" {
  bucket = aws_s3_bucket.demo_bucket.id

  # These should be true for security
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# INTENTIONAL MISCONFIGURATION: No encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "demo_bucket_encryption" {
  bucket = aws_s3_bucket.demo_bucket.id

  # Missing server-side encryption
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # Should use KMS
    }
  }
}

# INTENTIONAL MISCONFIGURATION: No versioning
resource "aws_s3_bucket_versioning" "demo_bucket_versioning" {
  bucket = aws_s3_bucket.demo_bucket.id
  versioning_configuration {
    status = "Disabled" # Should be "Enabled"
  }
}

# INTENTIONAL MISCONFIGURATION: Security group with overly permissive rules
resource "aws_security_group" "demo_sg" {
  name_prefix = "${var.project_name}-${var.environment}-sg"
  description = "Demo security group with intentional misconfigurations"
  vpc_id      = aws_vpc.demo_vpc.id

  # DANGEROUS: Allow all traffic from anywhere
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all TCP traffic from anywhere"
  }

  # DANGEROUS: Allow SSH from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access from anywhere"
  }

  # DANGEROUS: Allow RDP from anywhere
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP access from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Demo Security Group"
    # Missing environment and security tags
  }
}

# VPC Configuration
resource "aws_vpc" "demo_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-vpc"
    Environment = var.environment
  }
}

# INTENTIONAL MISCONFIGURATION: Public subnet without proper routing
resource "aws_subnet" "demo_public_subnet" {
  vpc_id                  = aws_vpc.demo_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true # This is intentionally public

  tags = {
    Name = "Demo Public Subnet"
    Type = "Public"
  }
}

# INTENTIONAL MISCONFIGURATION: EC2 instance with security issues
resource "aws_instance" "demo_instance" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.demo_public_subnet.id
  
  vpc_security_group_ids = [aws_security_group.demo_sg.id]
  
  # DANGEROUS: Instance profile with overly broad permissions
  iam_instance_profile = aws_iam_instance_profile.demo_profile.name
  
  # DANGEROUS: No encryption for root volume
  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = false # Should be true
    
    tags = {
      Name = "Demo Root Volume"
    }
  }

  # DANGEROUS: User data with secrets
  user_data = base64encode(<<-EOF
              #!/bin/bash
              # NEVER put secrets in user data!
              export DATABASE_PASSWORD="super_secret_password"
              export API_KEY="ak_1234567890abcdef"
              echo "Starting application..."
              EOF
  )

  tags = {
    Name        = "Demo Instance"
    Environment = var.environment
    # Missing security and compliance tags
  }
}

# INTENTIONAL MISCONFIGURATION: Overly permissive IAM role
resource "aws_iam_role" "demo_role" {
  name = "${var.project_name}-${var.environment}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# DANGEROUS: Policy with wildcard permissions
resource "aws_iam_role_policy" "demo_policy" {
  name = "${var.project_name}-${var.environment}-policy"
  role = aws_iam_role.demo_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"           # DANGEROUS: Allows all actions
        Resource = "*"         # DANGEROUS: On all resources
      }
    ]
  })
}

resource "aws_iam_instance_profile" "demo_profile" {
  name = "${var.project_name}-${var.environment}-profile"
  role = aws_iam_role.demo_role.name
}

# INTENTIONAL MISCONFIGURATION: RDS instance without encryption
resource "aws_db_instance" "demo_database" {
  identifier = "${var.project_name}-${var.environment}-db"
  
  engine         = "postgres"
  engine_version = "13.7"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp2"
  storage_encrypted     = false # Should be true
  
  db_name  = "demodb"
  username = "admin"
  password = "password123" # DANGEROUS: Hardcoded password
  
  # DANGEROUS: Publicly accessible
  publicly_accessible = true
  
  # DANGEROUS: Skip final snapshot
  skip_final_snapshot = true
  
  # DANGEROUS: No backup retention
  backup_retention_period = 0
  
  vpc_security_group_ids = [aws_security_group.demo_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.demo_subnet_group.name

  tags = {
    Name = "Demo Database"
    # Missing environment and security tags
  }
}

resource "aws_db_subnet_group" "demo_subnet_group" {
  name       = "${var.project_name}-${var.environment}-subnet-group"
  subnet_ids = [aws_subnet.demo_public_subnet.id, aws_subnet.demo_private_subnet.id]

  tags = {
    Name = "Demo DB Subnet Group"
  }
}

resource "aws_subnet" "demo_private_subnet" {
  vpc_id            = aws_vpc.demo_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "Demo Private Subnet"
    Type = "Private"
  }
}

# Azure Resources with Misconfigurations

# INTENTIONAL MISCONFIGURATION: Storage account without encryption
resource "azurerm_resource_group" "demo_rg" {
  name     = "${var.project_name}-${var.environment}-rg"
  location = "West US 2"

  tags = {
    Environment = var.environment
    Project     = var.project_name
  }
}

# DANGEROUS: Storage account with public access
resource "azurerm_storage_account" "demo_storage" {
  name                     = "${var.project_name}${var.environment}storage${random_id.storage_suffix.hex}"
  resource_group_name      = azurerm_resource_group.demo_rg.name
  location                 = azurerm_resource_group.demo_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # DANGEROUS: Allow public access
  public_network_access_enabled = true
  
  # DANGEROUS: No HTTPS requirement
  enable_https_traffic_only = false
  
  # Missing: infrastructure_encryption_enabled = true
  
  tags = {
    Environment = var.environment
  }
}

# DANGEROUS: Network security group with open rules
resource "azurerm_network_security_group" "demo_nsg" {
  name                = "${var.project_name}-${var.environment}-nsg"
  location            = azurerm_resource_group.demo_rg.location
  resource_group_name = azurerm_resource_group.demo_rg.name

  # DANGEROUS: Allow all inbound traffic
  security_rule {
    name                       = "AllowAll"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = var.environment
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Random IDs for unique naming
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "random_id" "storage_suffix" {
  byte_length = 4
}

# Outputs
output "s3_bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.demo_bucket.bucket
}

output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.demo_instance.id
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.demo_database.endpoint
  sensitive   = true
}

output "storage_account_name" {
  description = "Name of the Azure storage account"
  value       = azurerm_storage_account.demo_storage.name
}