#!/usr/bin/env python3
import os
import sys
import psutil
import argparse
import subprocess
import json
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from io import StringIO

class ProcessAnalyzer:
    def __init__(self, pid):
        try:
            self.process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            raise ValueError(f"Process {pid} not found")
    
    def analyze(self, enhanced=False):
        """Analyze process and return detailed information"""
        info = {}
        
        # Basic process info
        info['pid'] = self.process.pid
        info['name'] = self.process.name()
        info['status'] = self.process.status()
        
        # Execution details
        try:
            info['cmdline'] = ' '.join(self.process.cmdline())
            info['exe'] = self.process.exe()
            info['cwd'] = self.process.cwd()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info['cmdline'] = 'Access denied'
            info['exe'] = 'Access denied'
            info['cwd'] = 'Access denied'
        
        # Environment
        try:
            info['environ'] = dict(self.process.environ())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info['environ'] = 'Access denied'
        
        # Dependencies
        info['memory_maps'] = self._get_memory_maps()
        info['open_files'] = self._get_open_files()
        info['connections'] = self._get_connections()
        
        # Enhanced analysis for specialized applications
        if enhanced:
            if is_java_process(info):
                info['java_analysis'] = self._analyze_java_process(info)
            elif is_webserver_process(info):
                info['webserver_analysis'] = self._analyze_webserver_process(info)
        
        return info
    
    def _get_memory_maps(self):
        """Get shared libraries and memory mappings"""
        try:
            maps = []
            for mmap in self.process.memory_maps():
                maps.append({
                    'path': mmap.path,
                    'rss': mmap.rss,
                    'size': mmap.size
                })
            return maps
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return 'Access denied'
    
    def _get_open_files(self):
        """Get open file descriptors"""
        try:
            files = []
            for f in self.process.open_files():
                files.append({
                    'path': f.path,
                    'fd': f.fd,
                    'mode': f.mode if hasattr(f, 'mode') else 'unknown'
                })
            return files
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return 'Access denied'
    
    def _get_connections(self):
        """Get network connections"""
        try:
            conns = []
            for conn in self.process.connections():
                conns.append({
                    'fd': conn.fd,
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                })
            return conns
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return 'Access denied'
    
    def _analyze_java_process(self, info):
        """Enhanced analysis for Java processes"""
        analysis = {}
        analysis['jvm_config'] = self._parse_jvm_args(info)
        analysis['app_type'] = self._identify_java_app_type(info)
        analysis['jar_files'] = self._get_jar_files(info)
        analysis['db_connections'] = self._analyze_db_connections(info)
        analysis['config_files'] = self._get_config_files(info)
        analysis['security'] = self._analyze_security_settings(info)
        return analysis
    
    def _parse_jvm_args(self, info):
        """Parse JVM command line arguments"""
        if info['cmdline'] == 'Access denied':
            return 'Access denied'
        
        cmdline = info['cmdline'].split()
        jvm_config = {'heap_size': {}, 'gc_settings': [], 'system_props': {}, 'other_flags': []}
        
        for arg in cmdline:
            if arg.startswith('-Xmx'):
                jvm_config['heap_size']['max'] = arg[4:]
            elif arg.startswith('-Xms'):
                jvm_config['heap_size']['initial'] = arg[4:]
            elif arg.startswith('-XX:'):
                jvm_config['gc_settings'].append(arg)
            elif arg.startswith('-D'):
                if '=' in arg:
                    key, value = arg[2:].split('=', 1)
                    jvm_config['system_props'][key] = value
            elif arg.startswith('-'):
                jvm_config['other_flags'].append(arg)
        
        return jvm_config
    
    def _identify_java_app_type(self, info):
        """Identify type of Java application"""
        cmdline = info['cmdline']
        environ = info['environ']
        
        if cmdline == 'Access denied':
            return 'Unknown'
        
        if 'catalina' in cmdline.lower() or (isinstance(environ, dict) and 'CATALINA_HOME' in environ):
            return 'Apache Tomcat'
        elif 'spring' in cmdline.lower():
            return 'Spring Application'
        elif 'jetty' in cmdline.lower():
            return 'Eclipse Jetty'
        elif 'wildfly' in cmdline.lower() or 'jboss' in cmdline.lower():
            return 'WildFly/JBoss'
        elif '.jar' in cmdline:
            return 'Standalone JAR Application'
        else:
            return 'Java Application'
    
    def _get_jar_files(self, info):
        """Get loaded JAR files from memory maps"""
        jar_files = []
        if isinstance(info['memory_maps'], list):
            for mmap in info['memory_maps']:
                if mmap['path'].endswith('.jar'):
                    jar_files.append(mmap['path'])
        return jar_files
    
    def _analyze_db_connections(self, info):
        """Analyze database connections"""
        db_info = {'drivers': [], 'connections': []}
        
        # Check for database drivers in JAR files
        jar_files = self._get_jar_files(info)
        for jar in jar_files:
            if any(db in jar.lower() for db in ['mysql', 'postgresql', 'oracle', 'sqlite', 'h2', 'mongodb']):
                db_info['drivers'].append(jar)
        
        # Check network connections for database ports
        if isinstance(info['connections'], list):
            for conn in info['connections']:
                if conn.get('raddr'):
                    port = conn['raddr'].split(':')[-1] if ':' in conn['raddr'] else ''
                    if port in ['3306', '5432', '1521', '27017', '1433']:
                        db_info['connections'].append(conn)
        
        return db_info
    
    def _get_config_files(self, info):
        """Get configuration files"""
        config_files = []
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(ext in path for ext in ['.xml', '.properties', '.yml', '.yaml', '.conf']):
                    config_files.append(path)
        return config_files
    
    def _analyze_security_settings(self, info):
        """Analyze security settings"""
        security = {'ssl_enabled': False, 'security_manager': False, 'auth_config': []}
        
        cmdline = info['cmdline']
        if cmdline != 'Access denied' and 'java.security.manager' in cmdline:
            security['security_manager'] = True
        
        # Check for SSL/TLS configuration
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(ssl_file in path for ssl_file in ['keystore', 'truststore', '.p12', '.jks']):
                    security['ssl_enabled'] = True
                    security['auth_config'].append(path)
        
        return security
    
    def _analyze_webserver_process(self, info):
        """Enhanced analysis for web server processes"""
        analysis = {}
        analysis['server_type'] = self._identify_webserver_type(info)
        analysis['config_files'] = self._get_webserver_configs(info)
        analysis['virtual_hosts'] = self._analyze_virtual_hosts(info)
        analysis['ssl_config'] = self._analyze_webserver_ssl(info)
        analysis['modules'] = self._get_webserver_modules(info)
        analysis['log_files'] = self._get_webserver_logs(info)
        return analysis
    
    def _identify_webserver_type(self, info):
        """Identify type of web server"""
        cmdline = info['cmdline']
        name = info['name'].lower()
        
        if cmdline == 'Access denied':
            return 'Unknown'
        
        if name in ['httpd', 'apache2'] or 'httpd' in cmdline.lower():
            return 'Apache HTTP Server'
        elif name == 'nginx' or 'nginx' in cmdline.lower():
            return 'Nginx'
        elif name == 'haproxy' or 'haproxy' in cmdline.lower():
            return 'HAProxy'
        else:
            return 'Web Server'
    
    def _get_webserver_configs(self, info):
        """Get web server configuration files"""
        config_files = []
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(config in path for config in ['httpd.conf', 'apache2.conf', 'nginx.conf', 'haproxy.cfg', 'sites-enabled', 'sites-available', 'conf.d']):
                    config_files.append(path)
        return config_files
    
    def _analyze_virtual_hosts(self, info):
        """Analyze virtual host configurations"""
        vhosts = []
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(vhost in path for vhost in ['sites-enabled', 'sites-available', 'vhosts', 'conf.d']):
                    vhosts.append(path)
        return vhosts
    
    def _analyze_webserver_ssl(self, info):
        """Analyze SSL/TLS configuration"""
        ssl_config = {'ssl_enabled': False, 'cert_files': [], 'key_files': []}
        
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(ssl_file in path for ssl_file in ['.crt', '.pem', '.cert', 'ssl']):
                    ssl_config['ssl_enabled'] = True
                    if any(cert in path for cert in ['.crt', '.pem', '.cert']):
                        ssl_config['cert_files'].append(path)
                    elif '.key' in path:
                        ssl_config['key_files'].append(path)
        
        # Check for HTTPS ports
        if isinstance(info['connections'], list):
            for conn in info['connections']:
                if conn.get('laddr') and ':443' in conn['laddr']:
                    ssl_config['ssl_enabled'] = True
        
        return ssl_config
    
    def _get_webserver_modules(self, info):
        """Get loaded web server modules"""
        modules = []
        if isinstance(info['memory_maps'], list):
            for mmap in info['memory_maps']:
                path = mmap['path']
                if any(mod in path for mod in ['mod_', 'modules/', 'nginx/modules']):
                    modules.append(path)
        return modules
    
    def _get_webserver_logs(self, info):
        """Get web server log files"""
        log_files = []
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(log in path for log in ['access.log', 'error.log', 'access_log', 'error_log', '/var/log/']):
                    log_files.append(path)
        return log_files

def is_java_process(info):
    """Check if process is a Java application"""
    if info['cmdline'] == 'Access denied':
        return False
    
    cmdline = info['cmdline'].lower()
    return ('java' in cmdline and any(indicator in cmdline for indicator in 
           ['catalina', 'tomcat', 'spring', 'jetty', '.jar', 'wildfly', 'jboss']))

def is_webserver_process(info):
    """Check if process is a web server or reverse proxy"""
    if info['cmdline'] == 'Access denied':
        return False
    
    cmdline = info['cmdline'].lower()
    name = info['name'].lower()
    
    return (name in ['httpd', 'apache2', 'nginx', 'haproxy'] or
            any(indicator in cmdline for indicator in ['httpd', 'apache2', 'nginx', 'haproxy']))

def format_analysis(info):
    """Format analysis results as string"""
    output = StringIO()
    output.write(f"Process Analysis for PID {info['pid']}\n")
    output.write("=" * 50 + "\n")
    
    output.write(f"Name: {info['name']}\n")
    output.write(f"Status: {info['status']}\n")
    output.write(f"Command: {info['cmdline']}\n")
    output.write(f"Executable: {info['exe']}\n")
    output.write(f"Working Directory: {info['cwd']}\n")
    
    output.write("\nEnvironment Variables:\n")
    if isinstance(info['environ'], dict):
        for key, value in list(info['environ'].items())[:10]:
            output.write(f"  {key}={value}\n")
        if len(info['environ']) > 10:
            output.write(f"  ... and {len(info['environ']) - 10} more\n")
    else:
        output.write(f"  {info['environ']}\n")
    
    output.write(f"\nMemory Maps ({len(info['memory_maps']) if isinstance(info['memory_maps'], list) else 0}):\n")
    if isinstance(info['memory_maps'], list):
        for mmap in info['memory_maps'][:5]:
            output.write(f"  {mmap['path']} (RSS: {mmap['rss']} bytes)\n")
        if len(info['memory_maps']) > 5:
            output.write(f"  ... and {len(info['memory_maps']) - 5} more\n")
    else:
        output.write(f"  {info['memory_maps']}\n")
    
    output.write(f"\nOpen Files ({len(info['open_files']) if isinstance(info['open_files'], list) else 0}):\n")
    if isinstance(info['open_files'], list):
        for f in info['open_files'][:5]:
            output.write(f"  FD {f['fd']}: {f['path']} ({f['mode']})\n")
        if len(info['open_files']) > 5:
            output.write(f"  ... and {len(info['open_files']) - 5} more\n")
    else:
        output.write(f"  {info['open_files']}\n")
    
    output.write(f"\nNetwork Connections ({len(info['connections']) if isinstance(info['connections'], list) else 0}):\n")
    if isinstance(info['connections'], list):
        for conn in info['connections']:
            output.write(f"  {conn['family']}/{conn['type']}: {conn['laddr']} -> {conn['raddr']} ({conn['status']})\n")
    else:
        output.write(f"  {info['connections']}\n")
    
    # Java-specific analysis
    if 'java_analysis' in info:
        java = info['java_analysis']
        output.write(f"\n{'='*50}\n")
        output.write("JAVA APPLICATION ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        output.write(f"Application Type: {java['app_type']}\n")
        
        if isinstance(java['jvm_config'], dict):
            output.write("\nJVM Configuration:\n")
            if java['jvm_config']['heap_size']:
                for key, value in java['jvm_config']['heap_size'].items():
                    output.write(f"  Heap {key}: {value}\n")
            if java['jvm_config']['gc_settings']:
                output.write(f"  GC Settings: {', '.join(java['jvm_config']['gc_settings'][:3])}\n")
            if java['jvm_config']['system_props']:
                output.write("  Key System Properties:\n")
                for key, value in list(java['jvm_config']['system_props'].items())[:5]:
                    output.write(f"    {key}={value}\n")
        
        if java['jar_files']:
            output.write(f"\nLoaded JAR Files ({len(java['jar_files'])}):\n")
            for jar in java['jar_files'][:5]:
                output.write(f"  {jar}\n")
            if len(java['jar_files']) > 5:
                output.write(f"  ... and {len(java['jar_files']) - 5} more\n")
        
        if java['db_connections']['drivers']:
            output.write("\nDatabase Drivers:\n")
            for driver in java['db_connections']['drivers']:
                output.write(f"  {driver}\n")
        
        if java['db_connections']['connections']:
            output.write("\nDatabase Connections:\n")
            for conn in java['db_connections']['connections']:
                output.write(f"  {conn['laddr']} -> {conn['raddr']}\n")
        
        if java['config_files']:
            output.write(f"\nConfiguration Files ({len(java['config_files'])}):\n")
            for config in java['config_files'][:5]:
                output.write(f"  {config}\n")
            if len(java['config_files']) > 5:
                output.write(f"  ... and {len(java['config_files']) - 5} more\n")
        
        if isinstance(java['security'], dict):
            output.write("\nSecurity Settings:\n")
            output.write(f"  Security Manager: {'Enabled' if java['security']['security_manager'] else 'Disabled'}\n")
            output.write(f"  SSL/TLS: {'Enabled' if java['security']['ssl_enabled'] else 'Not detected'}\n")
            if java['security']['auth_config']:
                output.write("  Security Files:\n")
                for auth_file in java['security']['auth_config']:
                    output.write(f"    {auth_file}\n")
    
    # Web server-specific analysis
    if 'webserver_analysis' in info:
        web = info['webserver_analysis']
        output.write(f"\n{'='*50}\n")
        output.write("WEB SERVER ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        output.write(f"Server Type: {web['server_type']}\n")
        
        if web['config_files']:
            output.write(f"\nConfiguration Files ({len(web['config_files'])}):\n")
            for config in web['config_files'][:5]:
                output.write(f"  {config}\n")
            if len(web['config_files']) > 5:
                output.write(f"  ... and {len(web['config_files']) - 5} more\n")
        
        if web['virtual_hosts']:
            output.write(f"\nVirtual Hosts ({len(web['virtual_hosts'])}):\n")
            for vhost in web['virtual_hosts'][:5]:
                output.write(f"  {vhost}\n")
            if len(web['virtual_hosts']) > 5:
                output.write(f"  ... and {len(web['virtual_hosts']) - 5} more\n")
        
        if isinstance(web['ssl_config'], dict):
            output.write("\nSSL/TLS Configuration:\n")
            output.write(f"  SSL Enabled: {'Yes' if web['ssl_config']['ssl_enabled'] else 'No'}\n")
            if web['ssl_config']['cert_files']:
                output.write("  Certificate Files:\n")
                for cert in web['ssl_config']['cert_files'][:3]:
                    output.write(f"    {cert}\n")
            if web['ssl_config']['key_files']:
                output.write("  Key Files:\n")
                for key in web['ssl_config']['key_files'][:3]:
                    output.write(f"    {key}\n")
        
        if web['modules']:
            output.write(f"\nLoaded Modules ({len(web['modules'])}):\n")
            for module in web['modules'][:5]:
                output.write(f"  {module}\n")
            if len(web['modules']) > 5:
                output.write(f"  ... and {len(web['modules']) - 5} more\n")
        
        if web['log_files']:
            output.write(f"\nLog Files ({len(web['log_files'])}):\n")
            for log in web['log_files'][:5]:
                output.write(f"  {log}\n")
            if len(web['log_files']) > 5:
                output.write(f"  ... and {len(web['log_files']) - 5} more\n")
    
    return output.getvalue()

def is_system_process(proc_info):
    """Check if process is core OS functionality"""
    system_users = {'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 'nobody', 'systemd+', 'messagebus', 'systemd-network', 'systemd-resolve', 'systemd-timesync', 'syslog', '_apt', 'tss', 'uuidd', 'tcpdump', 'landscape', 'pollinate', 'sshd', 'systemd-coredump', 'lxd', 'dnsmasq', 'libvirt-qemu', 'libvirt-dnsmasq'}
    system_names = {'systemd', 'kthreadd', 'rcu_gp', 'rcu_par_gp', 'migration', 'ksoftirqd', 'watchdog', 'systemd-journal', 'systemd-udevd', 'systemd-network', 'systemd-resolve', 'systemd-timesync', 'dbus', 'NetworkManager', 'wpa_supplicant', 'sshd', 'cron', 'rsyslog', 'snapd', 'unattended-upgr', 'packagekitd', 'gdm', 'gnome-session', 'pulseaudio'}
    
    return (proc_info['user'] in system_users or 
            proc_info['name'] in system_names or 
            proc_info['name'].startswith(('kworker', 'ksoftirqd', 'migration', 'rcu_', 'watchdog')))

def select_process_interactive():
    """Interactive process selection menu"""
    all_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
        try:
            info = proc.info
            cmdline = ' '.join(info['cmdline']) if info['cmdline'] else ''
            runtime = __import__('time').time() - info['create_time']
            all_processes.append({
                'pid': info['pid'],
                'name': info['name'],
                'cmdline': cmdline[:60] + '...' if len(cmdline) > 60 else cmdline,
                'user': info['username'] or 'unknown',
                'runtime': runtime
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    filter_mode = 'user'  # Default: show user processes only
    filter_user = None
    sort_by = 'pid'
    page = 0
    page_size = 50
    
    while True:
        # Filter processes based on current filter mode
        if filter_mode == 'all':
            processes = all_processes
        elif filter_mode == 'user':
            processes = [p for p in all_processes if not is_system_process(p)]
        elif filter_mode == 'userid':
            processes = [p for p in all_processes if p['user'] == filter_user]
        
        # Sort processes based on current sort option
        if sort_by == 'pid':
            processes.sort(key=lambda x: x['pid'])
        elif sort_by == 'name':
            processes.sort(key=lambda x: x['name'].lower())
        elif sort_by == 'runtime':
            processes.sort(key=lambda x: x['runtime'], reverse=True)
        elif sort_by == 'user':
            processes.sort(key=lambda x: x['user'].lower())
        
        start_idx = page * page_size
        end_idx = min(start_idx + page_size, len(processes))
        current_page = processes[start_idx:end_idx]
        
        filter_desc = f"Filter: {filter_mode}" + (f" ({filter_user})" if filter_user else "")
        print(f"\nRunning Processes (Page {page + 1}/{(len(processes) - 1) // page_size + 1}) - {filter_desc} - Sorted by {sort_by}:")
        print(f"{'#':<4} {'PID':<8} {'User':<12} {'Name':<20} {'Command':<60}")
        print("-" * 104)
        
        for i, proc in enumerate(current_page):
            print(f"{i+1:<4} {proc['pid']:<8} {proc['user']:<12} {proc['name']:<20} {proc['cmdline']:<60}")
        
        nav_options = []
        if page > 0:
            nav_options.append("'p' for previous page")
        if end_idx < len(processes):
            nav_options.append("'n' for next page")
        nav_options.append("'s' to change sort")
        nav_options.append("'f' to change filter")
        
        prompt = f"\nSelect process number (1-{len(current_page)}), enter PID directly"
        if nav_options:
            prompt += f", {', '.join(nav_options)}"
        prompt += ": "
        
        try:
            choice = input(prompt).strip().lower()
            if choice == 'n' and end_idx < len(processes):
                page += 1
            elif choice == 'p' and page > 0:
                page -= 1
            elif choice == 's':
                print("\nSort options: 1) PID  2) Name  3) Runtime  4) User")
                sort_choice = input("Select sort option (1-4): ").strip()
                if sort_choice == '1':
                    sort_by = 'pid'
                elif sort_choice == '2':
                    sort_by = 'name'
                elif sort_choice == '3':
                    sort_by = 'runtime'
                elif sort_choice == '4':
                    sort_by = 'user'
                page = 0
            elif choice == 'f':
                print("\nFilter options: 1) User processes (default)  2) All processes  3) Specific user")
                filter_choice = input("Select filter option (1-3): ").strip()
                if filter_choice == '1':
                    filter_mode = 'user'
                    filter_user = None
                elif filter_choice == '2':
                    filter_mode = 'all'
                    filter_user = None
                elif filter_choice == '3':
                    filter_user = input("Enter username: ").strip()
                    if filter_user:
                        filter_mode = 'userid'
                page = 0
            elif choice.isdigit():
                num = int(choice)
                if 1 <= num <= len(current_page):
                    return current_page[num-1]['pid']
                else:
                    return num  # Assume it's a PID
            else:
                print("Invalid selection")
        except KeyboardInterrupt:
            print("\nSelection cancelled", file=sys.stderr)
            sys.exit(1)

def output_analysis(info, args):
    """Output analysis results based on specified method"""
    content = format_analysis(info)
    
    if args.output == 'stdout':
        print(content)
    elif args.output == 's3':
        import boto3
        s3 = boto3.client('s3')
        bucket, key = args.s3_uri.replace('s3://', '').split('/', 1)
        s3.put_object(Bucket=bucket, Key=key, Body=content)
    elif args.output == 'file':
        with open(args.file_path, 'w') as f:
            f.write(content)
    elif args.output == 'smtp':
        msg = MIMEText(content)
        msg['Subject'] = f'Process Analysis - PID {info["pid"]}'
        msg['From'] = args.smtp_from
        msg['To'] = args.smtp_to
        with smtplib.SMTP(args.smtp_server, args.smtp_port) as server:
            server.starttls()
            server.login(args.smtp_user, args.smtp_pass)
            server.send_message(msg)
    elif args.output == 'cloudwatch':
        import boto3
        logs = boto3.client('logs')
        logs.put_log_events(
            logGroupName=args.log_group,
            logStreamName=args.log_stream,
            logEvents=[{'timestamp': int(__import__('time').time() * 1000), 'message': content}]
        )

def main():
    parser = argparse.ArgumentParser(description='Analyze a process by PID')
    parser.add_argument('pid', type=int, nargs='?', help='Process ID to analyze')
    parser.add_argument('--non-interactive', action='store_true', help='Run without prompts (fails if not root)')
    
    # Output options
    parser.add_argument('--output', choices=['stdout', 's3', 'file', 'smtp', 'cloudwatch'], default='stdout', help='Output method')
    parser.add_argument('--s3-uri', help='S3 URI (s3://bucket/key)')
    parser.add_argument('--file-path', help='Filesystem path')
    parser.add_argument('--smtp-server', help='SMTP server')
    parser.add_argument('--smtp-port', type=int, default=587, help='SMTP port')
    parser.add_argument('--smtp-user', help='SMTP username')
    parser.add_argument('--smtp-pass', help='SMTP password')
    parser.add_argument('--smtp-to', help='Email recipient')
    parser.add_argument('--smtp-from', help='Email sender')
    parser.add_argument('--log-group', help='CloudWatch log group name')
    parser.add_argument('--log-stream', help='CloudWatch log stream name')
    args = parser.parse_args()
    
    # Handle missing PID in interactive mode
    if args.pid is None and not args.non_interactive:
        response = input("No PID specified. Select process interactively? (y/N): ")
        if response.lower() in ['y', 'yes']:
            args.pid = select_process_interactive()
        else:
            print("Error: PID required", file=sys.stderr)
            sys.exit(1)
    elif args.pid is None:
        print("Error: PID required in non-interactive mode", file=sys.stderr)
        sys.exit(1)
    
    if os.geteuid() != 0:
        if args.non_interactive:
            print("Error: Root privileges required. Run with sudo.", file=sys.stderr)
            sys.exit(1)
        response = input("Root privileges required for complete analysis. Escalate permissions? (y/N): ")
        if response.lower() in ['y', 'yes']:
            try:
                subprocess.run(['sudo', sys.executable] + sys.argv, check=True)
                sys.exit(0)
            except subprocess.CalledProcessError:
                print("Failed to escalate privileges", file=sys.stderr)
                sys.exit(1)
        else:
            print("Continuing with limited analysis...", file=sys.stderr)
    
    try:
        analyzer = ProcessAnalyzer(args.pid)
        info = analyzer.analyze()
        
        # Check for specialized processes and prompt for enhanced analysis
        enhanced = False
        if is_java_process(info) and not args.non_interactive:
            response = input(f"\nDetected Java application ({analyzer._identify_java_app_type(info)}). Include enhanced Java analysis? (y/N): ")
            if response.lower() in ['y', 'yes']:
                enhanced = True
        elif is_webserver_process(info) and not args.non_interactive:
            response = input(f"\nDetected web server ({analyzer._identify_webserver_type(info)}). Include enhanced web server analysis? (y/N): ")
            if response.lower() in ['y', 'yes']:
                enhanced = True
        
        if enhanced:
            info = analyzer.analyze(enhanced=True)
        
        output_analysis(info, args)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAnalysis interrupted", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()