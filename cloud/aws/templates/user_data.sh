#!/bin/bash
# User data script for EKS worker nodes with security hardening

# Enable logging
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "Starting user data script execution"

# Update system
yum update -y

# Configure CloudWatch agent for enhanced monitoring
yum install -y amazon-cloudwatch-agent

# Create CloudWatch agent configuration
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "cwagent"
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/messages",
                        "log_group_name": "/aws/eks/${cluster_name}/system",
                        "log_stream_name": "{instance_id}/messages"
                    },
                    {
                        "file_path": "/var/log/secure",
                        "log_group_name": "/aws/eks/${cluster_name}/security",
                        "log_stream_name": "{instance_id}/secure"
                    },
                    {
                        "file_path": "/var/log/audit/audit.log",
                        "log_group_name": "/aws/eks/${cluster_name}/audit",
                        "log_stream_name": "{instance_id}/audit"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "AWS/EKS/Sentinel",
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": [
                    "used_percent"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "diskio": {
                "measurement": [
                    "io_time"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "mem": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            },
            "netstat": {
                "measurement": [
                    "tcp_established",
                    "tcp_time_wait"
                ],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
    -s

# Enable audit logging
echo "-a always,exit -F arch=b64 -S execve -k exec" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S execve -k exec" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/passwd -p wa -k passwd_changes" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/shadow -p wa -k shadow_changes" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sudoers -p wa -k sudoers_changes" >> /etc/audit/rules.d/audit.rules

# Restart auditd
service auditd restart

# Install security tools
yum install -y \
    aide \
    clamav \
    clamav-update \
    fail2ban \
    rkhunter

# Configure AIDE for file integrity monitoring
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Update ClamAV signatures
freshclam

# Configure fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/secure
maxretry = 3
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Harden SSH configuration
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config

# Restart SSH service
systemctl restart sshd

# Set up filesystem permissions
chmod 700 /root
chmod 700 /home/*
find /tmp -type f -exec chmod 644 {} \;
find /tmp -type d -exec chmod 755 {} \;

# Configure kernel parameters for security
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf
echo "kernel.kptr_restrict = 1" >> /etc/sysctl.conf

# Apply sysctl changes
sysctl -p

# Configure log rotation
cat > /etc/logrotate.d/sentinel-security << 'EOF'
/var/log/sentinel/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF

# Install and configure osquery for endpoint monitoring
curl -L https://pkg.osquery.io/rpm/GPG | rpm --import -
yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
yum install -y osquery

# Configure osquery
cat > /etc/osquery/osquery.conf << 'EOF'
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": false,
    "log_result_events": true,
    "schedule_splay_percent": 10,
    "pidfile": "/var/osquery/osquery.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": false,
    "worker_threads": "2",
    "enable_monitor": true,
    "disable_events": false,
    "disable_audit": false,
    "audit_allow_config": true,
    "host_identifier": "hostname",
    "enable_syslog": true,
    "audit_allow_sockets": true,
    "schedule_default_interval": "3600"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    },
    "processes": {
      "query": "SELECT name, path, pid, on_disk, resident_size, user_time, system_time FROM processes;",
      "interval": 600
    },
    "network_connections": {
      "query": "SELECT pid, family, protocol, local_address, local_port, remote_address, remote_port, state FROM process_open_sockets WHERE state = 'LISTEN';",
      "interval": 600
    },
    "file_changes": {
      "query": "SELECT target_path, category, time, action FROM file_events WHERE path LIKE '/etc/%%' OR path LIKE '/bin/%%' OR path LIKE '/sbin/%%';",
      "interval": 300
    }
  },
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT user AS username FROM logged_in_users WHERE user <> '' ORDER BY time DESC LIMIT 1;"
    ]
  }
}
EOF

# Start osquery
systemctl enable osqueryd
systemctl start osqueryd

# Install container runtime security tools
mkdir -p /opt/sentinel/tools

# Download and install Falco for container runtime security
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list

# Configure file integrity monitoring with auditd rules for containers
echo "-w /var/lib/docker -p wa -k docker" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/docker -p wa -k docker" >> /etc/audit/rules.d/audit.rules
echo "-w /usr/bin/docker -p x -k docker" >> /etc/audit/rules.d/audit.rules
echo "-w /var/run/docker.sock -p wa -k docker" >> /etc/audit/rules.d/audit.rules

# Restart auditd to apply new rules
service auditd restart

# Create security monitoring script
cat > /opt/sentinel/security-monitor.sh << 'EOF'
#!/bin/bash
# Continuous security monitoring for EKS nodes

LOG_FILE="/var/log/sentinel/security-monitor.log"
mkdir -p /var/log/sentinel

while true; do
    echo "$(date): Running security checks..." >> $LOG_FILE
    
    # Check for suspicious processes
    ps aux | grep -E "(cryptomining|malware|suspicious)" >> $LOG_FILE
    
    # Check network connections
    netstat -tuln | grep -E "(LISTEN|ESTABLISHED)" >> $LOG_FILE
    
    # Check for failed login attempts
    grep "Failed password" /var/log/secure | tail -10 >> $LOG_FILE
    
    # Check disk usage
    df -h | grep -E "(9[0-9]%|100%)" >> $LOG_FILE
    
    # Sleep for 5 minutes
    sleep 300
done
EOF

chmod +x /opt/sentinel/security-monitor.sh

# Create systemd service for security monitoring
cat > /etc/systemd/system/sentinel-security-monitor.service << 'EOF'
[Unit]
Description=Sentinel Security Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/sentinel/security-monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl enable sentinel-security-monitor.service
systemctl start sentinel-security-monitor.service

# Configure automatic security updates
yum install -y yum-cron
sed -i 's/apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf
systemctl enable yum-cron
systemctl start yum-cron

echo "User data script execution completed successfully"