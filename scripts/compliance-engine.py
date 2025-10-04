#!/usr/bin/env python3
"""
Project Sentinel - Automated Compliance Engine
Provides automated mapping to CIS, NIST, and ISO27001 frameworks
Generates compliance scores and recommendations
"""

import json
import yaml
import subprocess
import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple
import argparse
import sys
import re

class ComplianceEngine:
    def __init__(self):
        self.compliance_frameworks = {
            'cis': self._load_cis_controls(),
            'nist': self._load_nist_controls(),
            'iso27001': self._load_iso27001_controls()
        }
        
        self.kubernetes_findings = []
        self.infrastructure_findings = []
        self.application_findings = []
        
    def _load_cis_controls(self) -> Dict[str, Any]:
        """Load CIS Kubernetes Benchmark controls"""
        return {
            "1.1.1": {
                "title": "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
                "level": 1,
                "category": "Master Node Configuration Files",
                "description": "The API server pod specification file controls how the API server is started on the master node.",
                "remediation": "Run the below command on the master node: chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml"
            },
            "1.1.2": {
                "title": "Ensure that the API server pod specification file ownership is set to root:root",
                "level": 1,
                "category": "Master Node Configuration Files",
                "description": "The API server pod specification file should be owned by root:root to prevent unauthorized access.",
                "remediation": "Run the below command on the master node: chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml"
            },
            "1.2.1": {
                "title": "Ensure that the --anonymous-auth argument is set to false",
                "level": 1,
                "category": "API Server",
                "description": "Disable anonymous requests to the API server",
                "remediation": "Edit the API server pod specification file and set --anonymous-auth=false"
            },
            "1.2.2": {
                "title": "Ensure that the --basic-auth-file argument is not set",
                "level": 1,
                "category": "API Server",
                "description": "Do not use basic authentication",
                "remediation": "Follow the documentation and configure alternate mechanisms for authentication"
            },
            "2.1.1": {
                "title": "Ensure that the --cert-file and --key-file arguments are set as appropriate",
                "level": 1,
                "category": "Etcd",
                "description": "Configure TLS encryption for etcd service",
                "remediation": "Follow the etcd service documentation and configure TLS encryption"
            },
            "3.1.1": {
                "title": "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate",
                "level": 1,
                "category": "Controller Manager",
                "description": "Activate garbage collector on pod termination, as appropriate",
                "remediation": "Edit the Controller Manager pod specification file and set --terminated-pod-gc-threshold"
            },
            "4.1.1": {
                "title": "Ensure that the kubelet service file permissions are set to 644 or more restrictive",
                "level": 1,
                "category": "Worker Nodes",
                "description": "The kubelet service file controls how the kubelet is started on the worker node",
                "remediation": "Run the below command on each worker node: chmod 644 /etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
            },
            "5.1.1": {
                "title": "Ensure that the cluster-admin role is only used where required",
                "level": 1,
                "category": "RBAC and Service Accounts",
                "description": "The cluster-admin role should not be used unnecessarily",
                "remediation": "Identify all clusterrolebindings to the cluster-admin role and remove them if not required"
            },
            "5.1.3": {
                "title": "Minimize wildcard use in Roles and ClusterRoles",
                "level": 1,
                "category": "RBAC and Service Accounts",
                "description": "Kubernetes Roles and ClusterRoles provide access control through permissions",
                "remediation": "Where possible replace any use of wildcards in clusterroles and roles with specific objects or actions"
            },
            "5.2.1": {
                "title": "Minimize the admission of privileged containers",
                "level": 1,
                "category": "Pod Security Policies",
                "description": "Do not generally permit containers to be run with the securityContext.privileged flag set to true",
                "remediation": "Create a PSP or Pod Security Standard that does not permit privileged containers and ensure it is applied"
            }
        }
    
    def _load_nist_controls(self) -> Dict[str, Any]:
        """Load NIST Cybersecurity Framework controls"""
        return {
            "ID.AM-1": {
                "title": "Physical devices and systems within the organization are inventoried",
                "function": "Identify",
                "category": "Asset Management",
                "subcategory": "ID.AM",
                "description": "Maintain an inventory of physical devices and systems within the organization"
            },
            "ID.AM-2": {
                "title": "Software platforms and applications within the organization are inventoried",
                "function": "Identify",
                "category": "Asset Management",
                "subcategory": "ID.AM",
                "description": "Maintain an inventory of software platforms and applications within the organization"
            },
            "PR.AC-1": {
                "title": "Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes",
                "function": "Protect",
                "category": "Access Control",
                "subcategory": "PR.AC",
                "description": "Manage identities and credentials throughout their lifecycle"
            },
            "PR.AC-3": {
                "title": "Remote access is managed",
                "function": "Protect",
                "category": "Access Control",
                "subcategory": "PR.AC",
                "description": "Control and monitor remote access to organizational systems"
            },
            "PR.AC-4": {
                "title": "Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties",
                "function": "Protect",
                "category": "Access Control",
                "subcategory": "PR.AC",
                "description": "Implement least privilege and separation of duties"
            },
            "PR.DS-1": {
                "title": "Data-at-rest is protected",
                "function": "Protect",
                "category": "Data Security",
                "subcategory": "PR.DS",
                "description": "Protect data while stored"
            },
            "PR.DS-2": {
                "title": "Data-in-transit is protected",
                "function": "Protect",
                "category": "Data Security",
                "subcategory": "PR.DS",
                "description": "Protect data while in transit"
            },
            "DE.CM-1": {
                "title": "The network is monitored to detect potential cybersecurity events",
                "function": "Detect",
                "category": "Security Continuous Monitoring",
                "subcategory": "DE.CM",
                "description": "Monitor network traffic for security events"
            },
            "DE.CM-3": {
                "title": "Personnel activity is monitored to detect potential cybersecurity events",
                "function": "Detect",
                "category": "Security Continuous Monitoring",
                "subcategory": "DE.CM",
                "description": "Monitor user activities for security events"
            },
            "RS.RP-1": {
                "title": "Response plan is executed during or after an incident",
                "function": "Respond",
                "category": "Response Planning",
                "subcategory": "RS.RP",
                "description": "Execute incident response procedures"
            }
        }
    
    def _load_iso27001_controls(self) -> Dict[str, Any]:
        """Load ISO 27001:2013 controls"""
        return {
            "A.5.1.1": {
                "title": "Information security policies",
                "domain": "Information Security Policies",
                "objective": "To provide management direction and support for information security in accordance with business requirements and relevant laws and regulations",
                "description": "A set of policies for information security shall be defined, approved by management, published and communicated to employees and relevant external parties"
            },
            "A.6.1.1": {
                "title": "Information security roles and responsibilities",
                "domain": "Organization of Information Security",
                "objective": "To ensure that information security responsibilities are defined and allocated",
                "description": "All information security responsibilities shall be defined and allocated"
            },
            "A.8.1.1": {
                "title": "Inventory of assets",
                "domain": "Asset Management",
                "objective": "To identify organizational assets and define appropriate protection responsibilities",
                "description": "Assets associated with information and information processing facilities shall be identified and an inventory of these assets shall be drawn up and maintained"
            },
            "A.8.2.1": {
                "title": "Classification of information",
                "domain": "Asset Management",
                "objective": "To ensure appropriate protection of information in accordance with its importance to the organization",
                "description": "Information shall be classified in terms of legal requirements, value, criticality and sensitivity to unauthorised disclosure or modification"
            },
            "A.9.1.1": {
                "title": "Access control policy",
                "domain": "Access Control",
                "objective": "To limit access to information and information processing facilities",
                "description": "An access control policy shall be established, documented and reviewed based on business and information security requirements"
            },
            "A.9.2.1": {
                "title": "User registration and de-registration",
                "domain": "Access Control",
                "objective": "To ensure authorized user access and to prevent unauthorized access to systems and services",
                "description": "A formal user registration and de-registration process shall be implemented to enable assignment of access rights"
            },
            "A.12.6.1": {
                "title": "Management of technical vulnerabilities",
                "domain": "Systems Acquisition, Development and Maintenance",
                "objective": "To prevent exploitation of technical vulnerabilities",
                "description": "Information about technical vulnerabilities of information systems being used shall be obtained in a timely fashion, the organization's exposure to such vulnerabilities evaluated and appropriate measures taken to address the associated risk"
            },
            "A.16.1.1": {
                "title": "Responsibilities and procedures",
                "domain": "Information Security Incident Management",
                "objective": "To ensure a consistent and effective approach to the management of information security incidents",
                "description": "Management responsibilities and procedures shall be established to ensure a quick, effective and orderly response to information security incidents"
            }
        }
    
    def scan_kubernetes_cluster(self) -> Dict[str, Any]:
        """Scan Kubernetes cluster for compliance issues"""
        print("🔍 Scanning Kubernetes cluster configuration...")
        
        findings = []
        
        try:
            # Check RBAC configurations
            rbac_result = subprocess.run(['kubectl', 'get', 'clusterrolebindings', '-o', 'json'], 
                                       capture_output=True, text=True, check=True)
            rbac_data = json.loads(rbac_result.stdout)
            
            for binding in rbac_data.get('items', []):
                if binding.get('roleRef', {}).get('name') == 'cluster-admin':
                    findings.append({
                        'control': 'CIS-5.1.1',
                        'severity': 'HIGH',
                        'title': 'Cluster-admin role binding found',
                        'description': f"ClusterRoleBinding '{binding.get('metadata', {}).get('name')}' grants cluster-admin privileges",
                        'remediation': 'Review and minimize cluster-admin role usage',
                        'resource': binding.get('metadata', {}).get('name'),
                        'namespace': binding.get('metadata', {}).get('namespace', 'cluster-wide')
                    })
            
            # Check for privileged containers
            pods_result = subprocess.run(['kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json'], 
                                       capture_output=True, text=True, check=True)
            pods_data = json.loads(pods_result.stdout)
            
            for pod in pods_data.get('items', []):
                for container in pod.get('spec', {}).get('containers', []):
                    security_context = container.get('securityContext', {})
                    if security_context.get('privileged'):
                        findings.append({
                            'control': 'CIS-5.2.1',
                            'severity': 'HIGH',
                            'title': 'Privileged container detected',
                            'description': f"Container '{container.get('name')}' in pod '{pod.get('metadata', {}).get('name')}' runs as privileged",
                            'remediation': 'Remove privileged flag unless absolutely necessary',
                            'resource': f"{pod.get('metadata', {}).get('name')}/{container.get('name')}",
                            'namespace': pod.get('metadata', {}).get('namespace')
                        })
            
            # Check service accounts
            sa_result = subprocess.run(['kubectl', 'get', 'serviceaccounts', '--all-namespaces', '-o', 'json'], 
                                     capture_output=True, text=True, check=True)
            sa_data = json.loads(sa_result.stdout)
            
            default_sa_count = sum(1 for sa in sa_data.get('items', []) 
                                 if sa.get('metadata', {}).get('name') == 'default')
            
            if default_sa_count > 0:
                findings.append({
                    'control': 'CIS-5.1.2',
                    'severity': 'MEDIUM',
                    'title': 'Default service accounts in use',
                    'description': f"Found {default_sa_count} default service accounts which may have unnecessary permissions",
                    'remediation': 'Create specific service accounts with minimal required permissions',
                    'resource': 'default service accounts',
                    'namespace': 'multiple'
                })
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Error scanning Kubernetes: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
        
        self.kubernetes_findings = findings
        return {
            'total_findings': len(findings),
            'critical': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'high': len([f for f in findings if f['severity'] == 'HIGH']),
            'medium': len([f for f in findings if f['severity'] == 'MEDIUM']),
            'low': len([f for f in findings if f['severity'] == 'LOW']),
            'findings': findings
        }
    
    def scan_infrastructure(self) -> Dict[str, Any]:
        """Scan infrastructure code for compliance issues"""
        print("🏗️ Scanning infrastructure code...")
        
        findings = []
        terraform_dir = Path("infra/terraform")
        
        if terraform_dir.exists():
            for tf_file in terraform_dir.glob("*.tf"):
                with open(tf_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Check for unencrypted S3 buckets
                    if 'aws_s3_bucket' in content and 'server_side_encryption_configuration' not in content:
                        findings.append({
                            'control': 'NIST-PR.DS-1',
                            'severity': 'HIGH',
                            'title': 'S3 bucket without encryption',
                            'description': f"S3 bucket in {tf_file.name} lacks server-side encryption",
                            'remediation': 'Add server_side_encryption_configuration block',
                            'resource': tf_file.name,
                            'file': str(tf_file)
                        })
                    
                    # Check for public S3 buckets
                    if 'public-read' in content or 'public-read-write' in content:
                        findings.append({
                            'control': 'CIS-2.1.1',
                            'severity': 'CRITICAL',
                            'title': 'S3 bucket with public access',
                            'description': f"S3 bucket in {tf_file.name} allows public access",
                            'remediation': 'Remove public ACLs and implement proper access controls',
                            'resource': tf_file.name,
                            'file': str(tf_file)
                        })
                    
                    # Check for overly permissive security groups
                    if '0.0.0.0/0' in content and 'aws_security_group_rule' in content:
                        findings.append({
                            'control': 'NIST-PR.AC-3',
                            'severity': 'HIGH',
                            'title': 'Overly permissive security group',
                            'description': f"Security group in {tf_file.name} allows access from 0.0.0.0/0",
                            'remediation': 'Restrict source IP ranges to specific networks',
                            'resource': tf_file.name,
                            'file': str(tf_file)
                        })
        
        self.infrastructure_findings = findings
        return {
            'total_findings': len(findings),
            'critical': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'high': len([f for f in findings if f['severity'] == 'HIGH']),
            'medium': len([f for f in findings if f['severity'] == 'MEDIUM']),
            'low': len([f for f in findings if f['severity'] == 'LOW']),
            'findings': findings
        }
    
    def scan_applications(self) -> Dict[str, Any]:
        """Scan application code for security issues"""
        print("🔐 Scanning application security...")
        
        findings = []
        app_dir = Path("demos/apps")
        
        if app_dir.exists():
            for py_file in app_dir.glob("**/*.py"):
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Check for hardcoded secrets
                    secret_patterns = [
                        (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
                        (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
                        (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret'),
                        (r'token\s*=\s*["\'][^"\']+["\']', 'Hardcoded token')
                    ]
                    
                    for pattern, description in secret_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append({
                                'control': 'ISO-A.9.4.3',
                                'severity': 'HIGH',
                                'title': 'Hardcoded credentials detected',
                                'description': f"{description} found in {py_file.name}",
                                'remediation': 'Use environment variables or secret management systems',
                                'resource': py_file.name,
                                'file': str(py_file)
                            })
                    
                    # Check for SQL injection vulnerabilities
                    if re.search(r'execute\s*\(\s*["\'][^"\']*%[^"\']*["\']', content):
                        findings.append({
                            'control': 'NIST-PR.DS-2',
                            'severity': 'CRITICAL',
                            'title': 'SQL injection vulnerability',
                            'description': f"Potential SQL injection in {py_file.name}",
                            'remediation': 'Use parameterized queries or ORM',
                            'resource': py_file.name,
                            'file': str(py_file)
                        })
                    
                    # Check for insecure direct object references
                    if 'request.args.get' in content and 'int(' in content:
                        findings.append({
                            'control': 'NIST-PR.AC-4',
                            'severity': 'MEDIUM',
                            'title': 'Potential insecure direct object reference',
                            'description': f"Direct parameter usage without validation in {py_file.name}",
                            'remediation': 'Implement proper access controls and input validation',
                            'resource': py_file.name,
                            'file': str(py_file)
                        })
        
        self.application_findings = findings
        return {
            'total_findings': len(findings),
            'critical': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'high': len([f for f in findings if f['severity'] == 'HIGH']),
            'medium': len([f for f in findings if f['severity'] == 'MEDIUM']),
            'low': len([f for f in findings if f['severity'] == 'LOW']),
            'findings': findings
        }
    
    def calculate_compliance_scores(self) -> Dict[str, float]:
        """Calculate compliance scores for each framework"""
        all_findings = self.kubernetes_findings + self.infrastructure_findings + self.application_findings
        
        if not all_findings:
            return {'cis': 100.0, 'nist': 100.0, 'iso27001': 100.0}
        
        # Calculate scores based on findings severity
        total_weight = len(all_findings)
        severity_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        total_penalty = sum(severity_weights.get(f['severity'], 1) for f in all_findings)
        max_possible_penalty = total_weight * 4  # All critical
        
        base_score = max(0, 100 - (total_penalty / max_possible_penalty * 100))
        
        # Framework-specific adjustments
        cis_findings = [f for f in all_findings if f['control'].startswith('CIS')]
        nist_findings = [f for f in all_findings if f['control'].startswith('NIST')]
        iso_findings = [f for f in all_findings if f['control'].startswith('ISO')]
        
        cis_penalty = sum(severity_weights.get(f['severity'], 1) for f in cis_findings)
        nist_penalty = sum(severity_weights.get(f['severity'], 1) for f in nist_findings)
        iso_penalty = sum(severity_weights.get(f['severity'], 1) for f in iso_findings)
        
        return {
            'cis': max(0, 100 - (cis_penalty / max(1, len(cis_findings)) * 25)),
            'nist': max(0, 100 - (nist_penalty / max(1, len(nist_findings)) * 25)),
            'iso27001': max(0, 100 - (iso_penalty / max(1, len(iso_findings)) * 25))
        }
    
    def generate_compliance_report(self, output_format: str = 'json') -> str:
        """Generate comprehensive compliance report"""
        
        # Run all scans
        k8s_results = self.scan_kubernetes_cluster()
        infra_results = self.scan_infrastructure()
        app_results = self.scan_applications()
        
        # Calculate scores
        scores = self.calculate_compliance_scores()
        
        # Compile report
        report = {
            'metadata': {
                'generated_at': datetime.datetime.now().isoformat(),
                'tool': 'Project Sentinel Compliance Engine',
                'version': '1.0.0'
            },
            'summary': {
                'total_findings': k8s_results['total_findings'] + infra_results['total_findings'] + app_results['total_findings'],
                'critical_findings': k8s_results['critical'] + infra_results['critical'] + app_results['critical'],
                'high_findings': k8s_results['high'] + infra_results['high'] + app_results['high'],
                'medium_findings': k8s_results['medium'] + infra_results['medium'] + app_results['medium'],
                'low_findings': k8s_results['low'] + infra_results['low'] + app_results['low']
            },
            'compliance_scores': scores,
            'scans': {
                'kubernetes': k8s_results,
                'infrastructure': infra_results,
                'applications': app_results
            },
            'recommendations': self._generate_recommendations()
        }
        
        # Format output
        if output_format.lower() == 'yaml':
            return yaml.dump(report, default_flow_style=False)
        elif output_format.lower() == 'json':
            return json.dumps(report, indent=2)
        else:
            return self._format_human_readable(report)
    
    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate prioritized recommendations based on findings"""
        recommendations = []
        
        all_findings = self.kubernetes_findings + self.infrastructure_findings + self.application_findings
        
        critical_findings = [f for f in all_findings if f['severity'] == 'CRITICAL']
        high_findings = [f for f in all_findings if f['severity'] == 'HIGH']
        
        if critical_findings:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'title': 'Address Critical Security Issues',
                'description': f"Found {len(critical_findings)} critical security issues that require immediate attention",
                'action': 'Review and remediate all critical findings before production deployment'
            })
        
        if high_findings:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Implement Security Best Practices',
                'description': f"Found {len(high_findings)} high-severity issues",
                'action': 'Implement security controls and follow framework guidelines'
            })
        
        # Framework-specific recommendations
        if any(f['control'].startswith('CIS') for f in all_findings):
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'CIS Kubernetes Benchmark Compliance',
                'description': 'Implement CIS Kubernetes Benchmark controls',
                'action': 'Follow CIS Kubernetes Benchmark v1.6.0 guidelines'
            })
        
        if any(f['control'].startswith('NIST') for f in all_findings):
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'NIST Cybersecurity Framework Implementation',
                'description': 'Align with NIST Cybersecurity Framework',
                'action': 'Implement NIST CSF controls across Identify, Protect, Detect, Respond, Recover functions'
            })
        
        return recommendations
    
    def _format_human_readable(self, report: Dict[str, Any]) -> str:
        """Format report in human-readable format"""
        output = []
        output.append("=" * 60)
        output.append("PROJECT SENTINEL - COMPLIANCE REPORT")
        output.append("=" * 60)
        output.append(f"Generated: {report['metadata']['generated_at']}")
        output.append("")
        
        # Summary
        summary = report['summary']
        output.append("EXECUTIVE SUMMARY")
        output.append("-" * 20)
        output.append(f"Total Findings: {summary['total_findings']}")
        output.append(f"  Critical: {summary['critical_findings']}")
        output.append(f"  High: {summary['high_findings']}")
        output.append(f"  Medium: {summary['medium_findings']}")
        output.append(f"  Low: {summary['low_findings']}")
        output.append("")
        
        # Compliance Scores
        scores = report['compliance_scores']
        output.append("COMPLIANCE SCORES")
        output.append("-" * 20)
        output.append(f"CIS Kubernetes Benchmark: {scores['cis']:.1f}%")
        output.append(f"NIST Cybersecurity Framework: {scores['nist']:.1f}%")
        output.append(f"ISO 27001:2013: {scores['iso27001']:.1f}%")
        output.append("")
        
        # Recommendations
        recommendations = report['recommendations']
        if recommendations:
            output.append("RECOMMENDATIONS")
            output.append("-" * 20)
            for rec in recommendations:
                output.append(f"[{rec['priority']}] {rec['title']}")
                output.append(f"  {rec['description']}")
                output.append(f"  Action: {rec['action']}")
                output.append("")
        
        return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(description='Project Sentinel Compliance Engine')
    parser.add_argument('--format', choices=['json', 'yaml', 'text'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--output', type=str, help='Output file path')
    parser.add_argument('--scan', choices=['all', 'kubernetes', 'infrastructure', 'applications'],
                       default='all', help='Scan scope (default: all)')
    
    args = parser.parse_args()
    
    try:
        engine = ComplianceEngine()
        
        print("🛡️ Starting Project Sentinel Compliance Engine...")
        
        # Generate report
        report = engine.generate_compliance_report(args.format)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"✅ Report saved to {args.output}")
        else:
            print(report)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()