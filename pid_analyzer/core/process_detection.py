"""
Process detection functions for identifying different types of applications.
"""

import os
from typing import Dict, Any


def is_java_process(info: Dict[str, Any]) -> bool:
    """Check if process is a Java application"""
    if info['cmdline'] == 'Access denied':
        return False
    
    cmdline = info['cmdline'].lower()
    return ('java' in cmdline and any(indicator in cmdline for indicator in 
           ['catalina', 'tomcat', 'spring', 'jetty', '.jar', 'wildfly', 'jboss']))


def is_webserver_process(info: Dict[str, Any]) -> bool:
    """Check if process is a web server or reverse proxy"""
    if info['cmdline'] == 'Access denied':
        return False
    
    cmdline = info['cmdline'].lower()
    name = info['name'].lower()
    
    return (name in ['httpd', 'apache2', 'nginx', 'haproxy'] or
            any(indicator in cmdline for indicator in ['httpd', 'apache2', 'nginx', 'haproxy']))


def is_redis_process(info: Dict[str, Any]) -> bool:
    """Check if process is a Redis server"""
    if info['cmdline'] == 'Access denied':
        return False
    
    cmdline = info['cmdline'].lower()
    name = info['name'].lower()
    
    # Check for Redis indicators
    redis_indicators = [
        'redis-server', 'redis-sentinel', 'redis-cluster',
        '/redis-server', '/redis-sentinel', 'redis.conf'
    ]
    
    return (name in ['redis-server', 'redis-sentinel'] or
            any(indicator in cmdline for indicator in redis_indicators))


def is_systemd_managed_process(info: Dict[str, Any]) -> bool:
    """Check if process is managed by systemd"""
    if info['cmdline'] == 'Access denied':
        return False
    
    # Check if process has a valid systemd cgroup path
    try:
        with open(f'/proc/{info["pid"]}/cgroup', 'r') as f:
            cgroup_content = f.read()
            
        # Look for systemd service patterns in cgroup
        lines = cgroup_content.strip().split('\n')
        for line in lines:
            # Modern systemd format: 0::/system.slice/service.service
            if '.service' in line and 'system.slice' in line:
                return True
            # Legacy systemd format: might have different patterns
            if 'systemd' in line and '.service' in line:
                return True
                
        return False
    except (FileNotFoundError, PermissionError, KeyError):
        return False


def is_system_process(proc_info: Dict[str, Any]) -> bool:
    """Check if process is core OS functionality"""
    system_users = {
        'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 
        'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 
        'nobody', 'systemd+', 'messagebus', 'systemd-network', 'systemd-resolve', 
        'systemd-timesync', 'syslog', '_apt', 'tss', 'uuidd', 'tcpdump', 
        'landscape', 'pollinate', 'sshd', 'systemd-coredump', 'lxd', 'dnsmasq', 
        'libvirt-qemu', 'libvirt-dnsmasq'
    }
    
    system_names = {
        'systemd', 'kthreadd', 'rcu_gp', 'rcu_par_gp', 'migration', 'ksoftirqd', 
        'watchdog', 'systemd-journal', 'systemd-udevd', 'systemd-network', 
        'systemd-resolve', 'systemd-timesync', 'dbus', 'NetworkManager', 
        'wpa_supplicant', 'sshd', 'cron', 'rsyslog', 'snapd', 'unattended-upgr', 
        'packagekitd', 'gdm', 'gnome-session', 'pulseaudio'
    }
    
    return (proc_info['user'] in system_users or 
            proc_info['name'] in system_names or 
            proc_info['name'].startswith(('kworker', 'ksoftirqd', 'migration', 'rcu_', 'watchdog')))
