#!/usr/bin/env python3
"""
Project Sentinel - Compliance Engine
Aggregates security scan results and generates compliance reports
"""

import json
import os
import sys
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Any
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ComplianceEngine:
    """Main compliance engine class"""
    
    def __init__(self, scan_dir: str):
        self.scan_dir = Path(scan_dir)
        self.compliance_data = {
            'scan_timestamp': datetime.datetime.now().isoformat(),
            'frameworks': {},
            'findings': [],
            'summary': {}
        }
        
        # Compliance framework mappings
        self.cis_controls = self._load_cis_controls()
        self.nist_controls = self._load_nist_controls()
        self.iso27001_controls = self._load_iso27001_controls()
    
    def _load_cis_controls(self) -> Dict:
        """Load CIS Controls mapping"""
        return {
            'IG1': {  # Implementation Group 1
                'CIS-1': 'Inventory and Control of Enterprise Assets',
                'CIS-2': 'Inventory and Control of Software Assets',
                'CIS-3': 'Data Protection',
                'CIS-4': 'Secure Configuration of Enterprise Assets and Software',
                'CIS-5': 'Account Management',
                'CIS-6': 'Access Control Management'
            },
            'IG2': {  # Implementation Group 2
                'CIS-7': 'Continuous Vulnerability Management',
                'CIS-8': 'Audit Log Management',
                'CIS-9': 'Email and Web Browser Protections',
                'CIS-10': 'Malware Defenses',
                'CIS-11': 'Data Recovery',
                'CIS-12': 'Network Infrastructure Management'
            },
            'IG3': {  # Implementation Group 3
                'CIS-13': 'Network Monitoring and Defense',
                'CIS-14': 'Security Awareness and Skills Training',
                'CIS-15': 'Service Provider Management',
                'CIS-16': 'Application Software Security',
                'CIS-17': 'Incident Response Management',
                'CIS-18': 'Penetration Testing'
            }
        }
    
    def _load_nist_controls(self) -> Dict:
        """Load NIST Cybersecurity Framework mapping"""
        return {
            'IDENTIFY': {
                'ID.AM': 'Asset Management',
                'ID.BE': 'Business Environment',
                'ID.GV': 'Governance',
                'ID.RA': 'Risk Assessment',
                'ID.RM': 'Risk Management Strategy',
                'ID.SC': 'Supply Chain Risk Management'
            },
            'PROTECT': {
                'PR.AC': 'Identity Management and Access Control',
                'PR.AT': 'Awareness and Training',
                'PR.DS': 'Data Security',
                'PR.IP': 'Information Protection Processes and Procedures',
                'PR.MA': 'Maintenance',
                'PR.PT': 'Protective Technology'
            },
            'DETECT': {
                'DE.AE': 'Anomalies and Events',
                'DE.CM': 'Security Continuous Monitoring',
                'DE.DP': 'Detection Processes'
            },
            'RESPOND': {
                'RS.RP': 'Response Planning',
                'RS.CO': 'Communications',
                'RS.AN': 'Analysis',
                'RS.MI': 'Mitigation',
                'RS.IM': 'Improvements'
            },
            'RECOVER': {
                'RC.RP': 'Recovery Planning',
                'RC.IM': 'Improvements',
                'RC.CO': 'Communications'
            }
        }
    
    def _load_iso27001_controls(self) -> Dict:
        """Load ISO 27001 controls mapping"""
        return {
            'A.5': 'Information security policies',
            'A.6': 'Organization of information security',
            'A.7': 'Human resource security',
            'A.8': 'Asset management',
            'A.9': 'Access control',
            'A.10': 'Cryptography',
            'A.11': 'Physical and environmental security',
            'A.12': 'Operations security',
            'A.13': 'Communications security',
            'A.14': 'System acquisition, development and maintenance',
            'A.15': 'Supplier relationships',
            'A.16': 'Information security incident management',
            'A.17': 'Information security aspects of business continuity management',
            'A.18': 'Compliance'
        }
    
    def analyze_checkov_results(self) -> None:
        """Analyze Checkov scan results"""
        logger.info("Analyzing Checkov results...")
        
        checkov_files = list(self.scan_dir.glob("**/checkov/*.json"))
        
        for file_path in checkov_files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                if 'results' in data and 'failed_checks' in data['results']:
                    for check in data['results']['failed_checks']:
                        finding = {
                            'source': 'checkov',
                            'type': 'infrastructure_misconfiguration',
                            'severity': self._map_checkov_severity(check.get('severity', 'MEDIUM')),
                            'title': check.get('check_name', 'Unknown Check'),
                            'description': check.get('description', ''),
                            'file': check.get('file_path', ''),
                            'line': check.get('file_line_range', []),
                            'check_id': check.get('check_id', ''),
                            'guideline': check.get('guideline', ''),
                            'compliance_mapping': self._map_to_compliance_frameworks(check)
                        }
                        self.compliance_data['findings'].append(finding)
                        
            except Exception as e:
                logger.error(f"Error processing Checkov file {file_path}: {e}")
    
    def analyze_trivy_results(self) -> None:
        """Analyze Trivy scan results"""
        logger.info("Analyzing Trivy results...")
        
        trivy_files = list(self.scan_dir.glob("**/trivy/*.json"))
        
        for file_path in trivy_files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                if 'Results' in data:
                    for result in data['Results']:
                        if 'Vulnerabilities' in result:
                            for vuln in result['Vulnerabilities']:
                                finding = {
                                    'source': 'trivy',
                                    'type': 'vulnerability',
                                    'severity': vuln.get('Severity', 'UNKNOWN'),
                                    'title': vuln.get('Title', vuln.get('VulnerabilityID', 'Unknown')),
                                    'description': vuln.get('Description', ''),
                                    'package': vuln.get('PkgName', ''),
                                    'version': vuln.get('InstalledVersion', ''),
                                    'fixed_version': vuln.get('FixedVersion', ''),
                                    'cve_id': vuln.get('VulnerabilityID', ''),
                                    'cvss_score': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 0),
                                    'compliance_mapping': self._map_vulnerability_to_compliance(vuln)
                                }
                                self.compliance_data['findings'].append(finding)
                        
                        if 'Secrets' in result:
                            for secret in result['Secrets']:
                                finding = {
                                    'source': 'trivy',
                                    'type': 'secret',
                                    'severity': 'HIGH',
                                    'title': f"Secret detected: {secret.get('Title', 'Unknown')}",
                                    'description': f"Potential secret found in {secret.get('StartLine', 'unknown location')}",
                                    'file': result.get('Target', ''),
                                    'line': secret.get('StartLine', 0),
                                    'rule_id': secret.get('RuleID', ''),
                                    'compliance_mapping': self._map_secret_to_compliance(secret)
                                }
                                self.compliance_data['findings'].append(finding)
                                
            except Exception as e:
                logger.error(f"Error processing Trivy file {file_path}: {e}")
    
    def analyze_tfsec_results(self) -> None:
        """Analyze tfsec scan results"""
        logger.info("Analyzing tfsec results...")
        
        tfsec_files = list(self.scan_dir.glob("**/tfsec/*.json"))
        
        for file_path in tfsec_files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                if 'results' in data:
                    for result in data['results']:
                        finding = {
                            'source': 'tfsec',
                            'type': 'terraform_misconfiguration',
                            'severity': result.get('severity', 'MEDIUM'),
                            'title': result.get('description', 'Unknown Issue'),
                            'description': result.get('long_id', ''),
                            'file': result.get('location', {}).get('filename', ''),
                            'line': result.get('location', {}).get('start_line', 0),
                            'rule_id': result.get('rule_id', ''),
                            'links': result.get('links', []),
                            'compliance_mapping': self._map_tfsec_to_compliance(result)
                        }
                        self.compliance_data['findings'].append(finding)
                        
            except Exception as e:
                logger.error(f"Error processing tfsec file {file_path}: {e}")
    
    def _map_checkov_severity(self, severity: str) -> str:
        """Map Checkov severity to standard levels"""
        mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW',
            'INFO': 'INFO'
        }
        return mapping.get(severity.upper(), 'MEDIUM')
    
    def _map_to_compliance_frameworks(self, check: Dict) -> Dict:
        """Map security check to compliance frameworks"""
        mapping = {
            'cis': [],
            'nist': [],
            'iso27001': []
        }
        
        check_id = check.get('check_id', '').lower()
        check_name = check.get('check_name', '').lower()
        
        # CIS mapping based on common patterns
        if any(pattern in check_name for pattern in ['access', 'iam', 'authentication']):
            mapping['cis'].extend(['CIS-5', 'CIS-6'])
            mapping['nist'].extend(['PR.AC'])
            mapping['iso27001'].extend(['A.9'])
        
        if any(pattern in check_name for pattern in ['encryption', 'kms', 'ssl', 'tls']):
            mapping['cis'].extend(['CIS-3'])
            mapping['nist'].extend(['PR.DS'])
            mapping['iso27001'].extend(['A.10'])
        
        if any(pattern in check_name for pattern in ['logging', 'audit', 'monitoring']):
            mapping['cis'].extend(['CIS-8'])
            mapping['nist'].extend(['DE.CM'])
            mapping['iso27001'].extend(['A.12'])
        
        if any(pattern in check_name for pattern in ['network', 'security group', 'firewall']):
            mapping['cis'].extend(['CIS-12'])
            mapping['nist'].extend(['PR.PT'])
            mapping['iso27001'].extend(['A.13'])
        
        return mapping
    
    def _map_vulnerability_to_compliance(self, vuln: Dict) -> Dict:
        """Map vulnerability to compliance frameworks"""
        return {
            'cis': ['CIS-7'],  # Continuous Vulnerability Management
            'nist': ['ID.RA', 'PR.IP'],  # Risk Assessment, Information Protection
            'iso27001': ['A.12', 'A.14']  # Operations security, System development
        }
    
    def _map_secret_to_compliance(self, secret: Dict) -> Dict:
        """Map secret exposure to compliance frameworks"""
        return {
            'cis': ['CIS-3', 'CIS-5'],  # Data Protection, Account Management
            'nist': ['PR.DS', 'PR.AC'],  # Data Security, Access Control
            'iso27001': ['A.9', 'A.10']  # Access control, Cryptography
        }
    
    def _map_tfsec_to_compliance(self, result: Dict) -> Dict:
        """Map tfsec finding to compliance frameworks"""
        rule_id = result.get('rule_id', '').lower()
        
        mapping = {
            'cis': [],
            'nist': [],
            'iso27001': []
        }
        
        if 'encryption' in rule_id or 'kms' in rule_id:
            mapping['cis'].extend(['CIS-3'])
            mapping['nist'].extend(['PR.DS'])
            mapping['iso27001'].extend(['A.10'])
        
        if 'access' in rule_id or 'iam' in rule_id:
            mapping['cis'].extend(['CIS-5', 'CIS-6'])
            mapping['nist'].extend(['PR.AC'])
            mapping['iso27001'].extend(['A.9'])
        
        if 'logging' in rule_id or 'audit' in rule_id:
            mapping['cis'].extend(['CIS-8'])
            mapping['nist'].extend(['DE.CM'])
            mapping['iso27001'].extend(['A.12'])
        
        return mapping
    
    def generate_compliance_summary(self) -> None:
        """Generate compliance summary statistics"""
        logger.info("Generating compliance summary...")
        
        # Count findings by severity
        severity_counts = {}
        for finding in self.compliance_data['findings']:
            severity = finding.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count findings by type
        type_counts = {}
        for finding in self.compliance_data['findings']:
            finding_type = finding.get('type', 'unknown')
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
        
        # Count findings by source
        source_counts = {}
        for finding in self.compliance_data['findings']:
            source = finding.get('source', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        # Generate compliance scores
        total_findings = len(self.compliance_data['findings'])
        critical_high = severity_counts.get('CRITICAL', 0) + severity_counts.get('HIGH', 0)
        
        compliance_score = max(0, 100 - (critical_high * 10) - (total_findings * 2))
        
        self.compliance_data['summary'] = {
            'total_findings': total_findings,
            'severity_breakdown': severity_counts,
            'type_breakdown': type_counts,
            'source_breakdown': source_counts,
            'compliance_score': compliance_score,
            'risk_level': self._calculate_risk_level(compliance_score, critical_high)
        }
        
        # Generate framework-specific summaries
        self._generate_framework_summaries()
    
    def _calculate_risk_level(self, score: int, critical_high: int) -> str:
        """Calculate overall risk level"""
        if critical_high > 10 or score < 50:
            return 'HIGH'
        elif critical_high > 5 or score < 70:
            return 'MEDIUM'
        elif critical_high > 0 or score < 85:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _generate_framework_summaries(self) -> None:
        """Generate summaries for each compliance framework"""
        frameworks = ['cis', 'nist', 'iso27001']
        
        for framework in frameworks:
            control_findings = {}
            
            for finding in self.compliance_data['findings']:
                compliance_mapping = finding.get('compliance_mapping', {})
                if framework in compliance_mapping:
                    for control in compliance_mapping[framework]:
                        if control not in control_findings:
                            control_findings[control] = []
                        control_findings[control].append(finding)
            
            # Calculate compliance percentage for framework
            if framework == 'cis':
                total_controls = len([control for group in self.cis_controls.values() for control in group.keys()])
            elif framework == 'nist':
                total_controls = len([control for category in self.nist_controls.values() for control in category.keys()])
            else:  # iso27001
                total_controls = len(self.iso27001_controls)
            
            affected_controls = len(control_findings)
            compliance_percentage = max(0, ((total_controls - affected_controls) / total_controls) * 100)
            
            self.compliance_data['frameworks'][framework] = {
                'total_controls': total_controls,
                'affected_controls': affected_controls,
                'compliance_percentage': round(compliance_percentage, 2),
                'control_findings': control_findings,
                'recommendations': self._generate_recommendations(framework, control_findings)
            }
    
    def _generate_recommendations(self, framework: str, control_findings: Dict) -> List[str]:
        """Generate remediation recommendations for framework"""
        recommendations = []
        
        # Priority order for different types of issues
        if any('secret' in str(findings) for findings in control_findings.values()):
            recommendations.append("CRITICAL: Immediately rotate exposed secrets and implement proper secret management")
        
        if any('CRITICAL' in str(findings) for findings in control_findings.values()):
            recommendations.append("HIGH: Address critical vulnerabilities in container images and dependencies")
        
        if 'CIS-3' in control_findings or 'PR.DS' in control_findings or 'A.10' in control_findings:
            recommendations.append("Enable encryption at rest and in transit for all data stores")
        
        if 'CIS-5' in control_findings or 'PR.AC' in control_findings or 'A.9' in control_findings:
            recommendations.append("Implement least privilege access controls and regular access reviews")
        
        if 'CIS-8' in control_findings or 'DE.CM' in control_findings or 'A.12' in control_findings:
            recommendations.append("Enable comprehensive logging and monitoring for security events")
        
        recommendations.append("Regular security assessments and compliance monitoring")
        recommendations.append("Implement infrastructure as code security scanning in CI/CD pipeline")
        
        return recommendations
    
    def save_results(self, output_file: str) -> None:
        """Save compliance results to JSON file"""
        logger.info(f"Saving results to {output_file}")
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(self.compliance_data, f, indent=2, default=str)
    
    def generate_html_report(self, output_file: str) -> None:
        """Generate HTML compliance report"""
        logger.info(f"Generating HTML report: {output_file}")
        
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Project Sentinel - Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .framework { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .risk-high { color: #e74c3c; font-weight: bold; }
        .risk-medium { color: #f39c12; font-weight: bold; }
        .risk-low { color: #27ae60; font-weight: bold; }
        .risk-minimal { color: #2ecc71; font-weight: bold; }
        .score { font-size: 2em; font-weight: bold; text-align: center; padding: 20px; }
        .findings { margin: 20px 0; }
        .finding { background: #ecf0f1; padding: 10px; margin: 10px 0; border-left: 4px solid #3498db; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #e67e22; }
        .medium { border-left-color: #f39c12; }
        .low { border-left-color: #27ae60; }
        .chart { width: 100%; height: 300px; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .progress-bar { width: 100%; background-color: #ecf0f1; border-radius: 10px; }
        .progress { height: 20px; border-radius: 10px; text-align: center; line-height: 20px; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Project Sentinel - Security Compliance Report</h1>
        <p>Generated on: {scan_timestamp}</p>
        <p>Enterprise-grade cloud security assessment results</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="score">
            Compliance Score: {compliance_score}%
            <div class="risk-{risk_class}">Risk Level: {risk_level}</div>
        </div>
        
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Security Findings</td><td>{total_findings}</td></tr>
            <tr><td>Critical Issues</td><td>{critical_count}</td></tr>
            <tr><td>High Severity Issues</td><td>{high_count}</td></tr>
            <tr><td>Medium Severity Issues</td><td>{medium_count}</td></tr>
            <tr><td>Low Severity Issues</td><td>{low_count}</td></tr>
        </table>
    </div>
    
    {framework_sections}
    
    <div class="findings">
        <h2>Top Priority Findings</h2>
        {priority_findings}
    </div>
    
    <div class="summary">
        <h2>Recommendations</h2>
        <ul>
            <li>Immediately address all CRITICAL and HIGH severity vulnerabilities</li>
            <li>Implement proper secret management using HashiCorp Vault</li>
            <li>Enable encryption for all data at rest and in transit</li>
            <li>Implement least privilege access controls</li>
            <li>Enable comprehensive security logging and monitoring</li>
            <li>Regular security assessments and compliance reviews</li>
        </ul>
    </div>
</body>
</html>
        """
        
        # Prepare template variables
        summary = self.compliance_data['summary']
        severity_breakdown = summary.get('severity_breakdown', {})
        
        risk_class = summary.get('risk_level', 'MEDIUM').lower()
        
        # Generate framework sections
        framework_sections = ""
        for framework, data in self.compliance_data['frameworks'].items():
            framework_name = framework.upper()
            compliance_pct = data['compliance_percentage']
            color = '#e74c3c' if compliance_pct < 70 else '#f39c12' if compliance_pct < 85 else '#27ae60'
            
            framework_sections += f"""
            <div class="framework">
                <h3>{framework_name} Compliance</h3>
                <div class="progress-bar">
                    <div class="progress" style="width: {compliance_pct}%; background-color: {color};">
                        {compliance_pct:.1f}%
                    </div>
                </div>
                <p>Controls Affected: {data['affected_controls']} / {data['total_controls']}</p>
                <h4>Key Recommendations:</h4>
                <ul>
                    {"".join(f"<li>{rec}</li>" for rec in data['recommendations'][:3])}
                </ul>
            </div>
            """
        
        # Generate priority findings
        priority_findings = ""
        high_priority = [f for f in self.compliance_data['findings'] 
                        if f.get('severity') in ['CRITICAL', 'HIGH']][:10]
        
        for finding in high_priority:
            severity_class = finding.get('severity', 'medium').lower()
            priority_findings += f"""
            <div class="finding {severity_class}">
                <strong>{finding.get('title', 'Unknown Issue')}</strong><br>
                <em>Source: {finding.get('source', 'unknown')} | Severity: {finding.get('severity', 'UNKNOWN')}</em><br>
                {finding.get('description', 'No description available')[:200]}...
            </div>
            """
        
        # Fill template
        html_content = html_template.format(
            scan_timestamp=self.compliance_data['scan_timestamp'],
            compliance_score=summary.get('compliance_score', 0),
            risk_level=summary.get('risk_level', 'UNKNOWN'),
            risk_class=risk_class,
            total_findings=summary.get('total_findings', 0),
            critical_count=severity_breakdown.get('CRITICAL', 0),
            high_count=severity_breakdown.get('HIGH', 0),
            medium_count=severity_breakdown.get('MEDIUM', 0),
            low_count=severity_breakdown.get('LOW', 0),
            framework_sections=framework_sections,
            priority_findings=priority_findings
        )
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def run_analysis(self) -> None:
        """Run complete compliance analysis"""
        logger.info("Starting compliance analysis...")
        
        # Analyze scan results
        self.analyze_checkov_results()
        self.analyze_trivy_results()
        self.analyze_tfsec_results()
        
        # Generate summary
        self.generate_compliance_summary()
        
        logger.info(f"Analysis complete. Found {len(self.compliance_data['findings'])} total findings")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Project Sentinel Compliance Engine')
    parser.add_argument('--scan-dir', required=True, help='Directory containing scan results')
    parser.add_argument('--output', default='compliance/compliance-report.json', help='Output JSON file')
    parser.add_argument('--html-output', default='compliance/compliance-report.html', help='Output HTML file')
    parser.add_argument('--framework', choices=['cis', 'nist', 'iso27001', 'all'], default='all',
                       help='Compliance framework to analyze')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.scan_dir):
        logger.error(f"Scan directory does not exist: {args.scan_dir}")
        sys.exit(1)
    
    # Initialize compliance engine
    engine = ComplianceEngine(args.scan_dir)
    
    # Run analysis
    engine.run_analysis()
    
    # Save results
    engine.save_results(args.output)
    engine.generate_html_report(args.html_output)
    
    # Print summary
    summary = engine.compliance_data['summary']
    print(f"\n🛡️ Project Sentinel Compliance Analysis Complete")
    print(f"Total Findings: {summary.get('total_findings', 0)}")
    print(f"Compliance Score: {summary.get('compliance_score', 0)}%")
    print(f"Risk Level: {summary.get('risk_level', 'UNKNOWN')}")
    print(f"Reports saved to: {args.output} and {args.html_output}")


if __name__ == '__main__':
    main()