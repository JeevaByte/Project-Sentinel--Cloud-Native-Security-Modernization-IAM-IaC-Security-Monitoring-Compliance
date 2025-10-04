# AWS EKS Outputs

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "cluster_iam_role_name" {
  description = "IAM role name associated with EKS cluster"
  value       = module.eks.cluster_iam_role_name
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
}

output "cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_version" {
  description = "The Kubernetes version for the EKS cluster"
  value       = module.eks.cluster_version
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster for the OpenID Connect identity provider"
  value       = module.eks.cluster_oidc_issuer_url
}

output "node_groups" {
  description = "EKS node groups"
  value       = module.eks.eks_managed_node_groups
  sensitive   = true
}

output "vpc_id" {
  description = "ID of the VPC where the cluster is deployed"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

# Security service outputs
output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = aws_guardduty_detector.sentinel.id
}

output "config_configuration_recorder_name" {
  description = "Name of the Config configuration recorder"
  value       = aws_config_configuration_recorder.sentinel.name
}

output "security_hub_account_id" {
  description = "AWS Security Hub account ID"
  value       = aws_securityhub_account.sentinel.id
}

# CloudWatch outputs
output "cluster_logs_cloudwatch_log_group_name" {
  description = "Name of cloudwatch log group for cluster logs"
  value       = aws_cloudwatch_log_group.cluster_logs.name
}

output "application_logs_cloudwatch_log_group_name" {
  description = "Name of cloudwatch log group for application logs"
  value       = aws_cloudwatch_log_group.application_logs.name
}

# ECR outputs
output "ecr_repository_urls" {
  description = "URLs of the ECR repositories"
  value = {
    for name, repo in aws_ecr_repository.sentinel_apps : name => repo.repository_url
  }
}

# Load Balancer outputs
output "load_balancer_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.sentinel_alb.dns_name
}

output "load_balancer_zone_id" {
  description = "Zone ID of the load balancer"
  value       = aws_lb.sentinel_alb.zone_id
}

output "load_balancer_arn" {
  description = "ARN of the load balancer"
  value       = aws_lb.sentinel_alb.arn
}

# S3 outputs
output "config_s3_bucket_name" {
  description = "Name of the S3 bucket for Config"
  value       = aws_s3_bucket.config.bucket
}

output "alb_logs_s3_bucket_name" {
  description = "Name of the S3 bucket for ALB logs"
  value       = aws_s3_bucket.alb_logs.bucket
}

# KMS outputs
output "kms_key_id" {
  description = "KMS key ID for encryption"
  value       = aws_kms_key.logs.key_id
}

output "kms_key_arn" {
  description = "KMS key ARN for encryption"
  value       = aws_kms_key.logs.arn
}

# IAM outputs
output "sentinel_admin_role_arn" {
  description = "ARN of the Sentinel admin IAM role"
  value       = aws_iam_role.sentinel_admin.arn
}

output "config_role_arn" {
  description = "ARN of the Config IAM role"
  value       = aws_iam_role.config.arn
}

# Kubectl configuration command
output "kubectl_config_command" {
  description = "Command to update kubeconfig"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

# Grafana and Prometheus access URLs (to be updated after deployment)
output "monitoring_urls" {
  description = "URLs for monitoring services (update after deployment)"
  value = {
    grafana_url    = "http://${aws_lb.sentinel_alb.dns_name}/grafana"
    prometheus_url = "http://${aws_lb.sentinel_alb.dns_name}/prometheus"
    demo_app_url   = "http://${aws_lb.sentinel_alb.dns_name}/demo"
  }
}

# Security recommendations
output "security_recommendations" {
  description = "Post-deployment security recommendations"
  value = [
    "1. Configure GuardDuty findings notifications",
    "2. Set up Security Hub custom insights and dashboards",
    "3. Configure Config compliance rules for your security standards",
    "4. Review and customize CloudWatch alarms",
    "5. Set up AWS SSO integration for cluster access",
    "6. Configure backup policies for persistent volumes",
    "7. Enable AWS CloudTrail for API call logging",
    "8. Configure network ACLs for additional security"
  ]
}