#!/usr/bin/env python3
"""
PY-PID-ANALYZER - Linux Process Analysis Utility

Copyright (c) 2024 PY-PID-ANALYZER

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

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

def is_redis_process(info):
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

def is_systemd_managed_process(info):
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
        info['shared_libraries'] = self._get_shared_libraries()
        
        # Enhanced analysis for specialized applications
        if enhanced:
            if is_java_process(info):
                info['java_analysis'] = self._analyze_java_process(info)
            if is_webserver_process(info):
                info['webserver_analysis'] = self._analyze_webserver_process(info)
            if is_redis_process(info):
                info['redis_analysis'] = self._analyze_redis_process(info)
        
        # Always include systemd analysis for systemd-managed processes
        if is_systemd_managed_process(info):
            info['systemd_analysis'] = self._analyze_systemd_process(info)
        else:
            # For non-systemd processes, analyze launch method and suggest systemd migration
            info['launch_analysis'] = self._analyze_process_launch(info)
            info['systemd_suggestion'] = self._generate_systemd_suggestion(info)
        
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
            for conn in self.process.net_connections():
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
    
    def _get_shared_libraries(self):
        """Get shared libraries used by the process"""
        try:
            libraries = {
                'system_libraries': [],
                'user_libraries': [],
                'language_specific': [],
                'total_count': 0,
                'unique_directories': set()
            }
            
            # Common system library directories
            system_lib_paths = [
                '/lib/', '/lib64/', '/usr/lib/', '/usr/lib64/',
                '/usr/local/lib/', '/usr/local/lib64/',
                '/lib/x86_64-linux-gnu/', '/usr/lib/x86_64-linux-gnu/'
            ]
            
            # Language-specific library patterns
            language_patterns = {
                'python': ['/python', 'site-packages', '.so'],
                'java': ['.jar', '/java/'],
                'node': ['/node_modules/', '/nodejs/'],
                'ruby': ['/ruby/', '/gems/'],
                'perl': ['/perl/'],
                'go': ['/go/'],
                'rust': ['/rust/'],
                'dotnet': ['/dotnet/', '.dll']
            }
            
            for mmap in self.process.memory_maps():
                path = mmap.path
                libraries['total_count'] += 1
                
                # Skip non-library entries
                if not path or path in ['[anon]', '[heap]', '[stack]', '[vdso]', '[vsyscall]']:
                    continue
                
                # Extract directory for analysis
                directory = os.path.dirname(path)
                libraries['unique_directories'].add(directory)
                
                # Classify the library
                lib_info = {
                    'path': path,
                    'real_path': None,
                    'size': mmap.size,
                    'rss': mmap.rss,
                    'category': 'unknown'
                }
                
                # Get real path (following symlinks)
                try:
                    if os.path.exists(path):
                        lib_info['real_path'] = os.path.realpath(path)
                    else:
                        lib_info['real_path'] = 'Path not accessible'
                except (OSError, PermissionError):
                    lib_info['real_path'] = 'Cannot resolve'
                
                # Check if it's a system library
                is_system_lib = any(sys_path in path for sys_path in system_lib_paths)
                
                if is_system_lib:
                    lib_info['category'] = 'system'
                    
                    # Further categorize system libraries
                    if any(pattern in path.lower() for pattern in ['libc.', 'libm.', 'libpthread.', 'libdl.', 'librt.']):
                        lib_info['subcategory'] = 'core_system'
                    elif any(pattern in path.lower() for pattern in ['libssl.', 'libcrypto.', 'libgnutls.']):
                        lib_info['subcategory'] = 'crypto'
                    elif any(pattern in path.lower() for pattern in ['libx11.', 'libgtk.', 'libqt.', 'libgl.']):
                        lib_info['subcategory'] = 'gui'
                    elif any(pattern in path.lower() for pattern in ['libz.', 'libbz2.', 'liblzma.']):
                        lib_info['subcategory'] = 'compression'
                    elif any(pattern in path.lower() for pattern in ['libdb.', 'libsqlite.', 'libmysql.', 'libpq.']):
                        lib_info['subcategory'] = 'database'
                    elif any(pattern in path.lower() for pattern in ['libcurl.', 'libexpat.', 'libxml.']):
                        lib_info['subcategory'] = 'network'
                    else:
                        lib_info['subcategory'] = 'other_system'
                    
                    libraries['system_libraries'].append(lib_info)
                
                # Check for language-specific libraries
                elif any(any(pattern in path.lower() for pattern in patterns) 
                        for patterns in language_patterns.values()):
                    lib_info['category'] = 'language_specific'
                    
                    for lang, patterns in language_patterns.items():
                        if any(pattern in path.lower() for pattern in patterns):
                            lib_info['language'] = lang
                            break
                    
                    libraries['language_specific'].append(lib_info)
                
                # Everything else is user/application library
                else:
                    lib_info['category'] = 'user'
                    libraries['user_libraries'].append(lib_info)
            
            # Convert set to sorted list for consistent output
            libraries['unique_directories'] = sorted(list(libraries['unique_directories']))
            
            # Sort libraries by RSS (memory usage) descending
            for category in ['system_libraries', 'user_libraries', 'language_specific']:
                libraries[category].sort(key=lambda x: x['rss'], reverse=True)
            
            return libraries
            
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
    
    def _analyze_systemd_process(self, info):
        """Enhanced analysis for systemd-managed processes"""
        analysis = {}
        analysis['service_info'] = self._get_systemd_service_info(info)
        analysis['unit_file'] = self._get_systemd_unit_file(info)
        analysis['service_status'] = self._get_systemd_service_status(info)
        analysis['dependencies'] = self._get_systemd_dependencies(info)
        analysis['resource_limits'] = self._get_systemd_resource_limits(info)
        analysis['recent_logs'] = self._get_systemd_recent_logs(info)
        analysis['cgroup_info'] = self._get_systemd_cgroup_info(info)
        return analysis
    
    def _get_systemd_service_info(self, info):
        """Get basic systemd service information"""
        try:
            # Try to find the service name from cgroup or process hierarchy
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Unable to determine service name'
            
            # Get service information using systemctl
            result = subprocess.run(['systemctl', 'show', service_name, '--no-pager'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                service_info = {}
                for line in result.stdout.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        service_info[key] = value
                return service_info
            else:
                return f'Service not found or access denied: {service_name}'
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return 'systemctl command failed or not available'
    
    def _detect_systemd_service_name(self, info):
        """Detect systemd service name from various sources"""
        try:
            # Method 1: Check cgroup information (modern systemd format) - most reliable
            with open(f'/proc/{self.process.pid}/cgroup', 'r') as f:
                cgroup_data = f.read()
                for line in cgroup_data.split('\n'):
                    # Modern systemd cgroup format: 0::/system.slice/service.service
                    if '.service' in line:
                        parts = line.split('/')
                        for part in parts:
                            if part.endswith('.service'):
                                # Verify this is a real service by checking with systemctl
                                try:
                                    result = subprocess.run(['systemctl', 'show', part, '-p', 'Id', '--no-pager'], 
                                                          capture_output=True, text=True, timeout=3)
                                    if result.returncode == 0 and f'Id={part}' in result.stdout:
                                        return part
                                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                                    pass
                    # Legacy systemd cgroup format: systemd:/system.slice/service.service
                    elif 'systemd:' in line and '.service' in line:
                        parts = line.split('/')
                        for part in parts:
                            if part.endswith('.service'):
                                try:
                                    result = subprocess.run(['systemctl', 'show', part, '-p', 'Id', '--no-pager'], 
                                                          capture_output=True, text=True, timeout=3)
                                    if result.returncode == 0 and f'Id={part}' in result.stdout:
                                        return part
                                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                                    pass
            
            # Method 2: Try using the process name directly as service name (with verification)
            name = info['name']
            
            # Skip generic names that are unlikely to be services
            generic_names = ['python3', 'python', 'bash', 'sh', 'zsh', 'fish', 'node', 'java', 'perl', 'ruby']
            if name.lower() in generic_names:
                return None
            
            # First try exact process name + .service
            potential_service = f'{name}.service'
            try:
                # Verify if this service actually exists and is real
                result = subprocess.run(['systemctl', 'show', potential_service, '-p', 'Id', '--no-pager'], 
                                      capture_output=True, text=True, timeout=3)
                if result.returncode == 0 and f'Id={potential_service}' in result.stdout:
                    return potential_service
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Method 3: Check common service name patterns (with verification)
            cmdline = info['cmdline']
            
            # Common service name mappings
            service_mappings = {
                'httpd': 'httpd.service',
                'apache2': 'apache2.service',
                'nginx': 'nginx.service',
                'sshd': 'sshd.service',
                'mysqld': 'mysqld.service',
                'postgres': 'postgresql.service',
                'mongod': 'mongod.service',
                'redis-server': 'redis.service',
                'dockerd': 'docker.service'
            }
            
            if name in service_mappings:
                potential_service = service_mappings[name]
                try:
                    result = subprocess.run(['systemctl', 'show', potential_service, '-p', 'Id', '--no-pager'], 
                                          capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and f'Id={potential_service}' in result.stdout:
                        return potential_service
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            # Method 4: Extract from command line executable path (with verification)
            if isinstance(cmdline, str) and 'systemd' not in cmdline:
                cmd_parts = cmdline.split()
                if cmd_parts:
                    base_name = os.path.basename(cmd_parts[0])
                    if base_name != name and base_name.lower() not in generic_names:
                        # Try the executable name as service
                        potential_service = f'{base_name}.service'
                        try:
                            result = subprocess.run(['systemctl', 'show', potential_service, '-p', 'Id', '--no-pager'], 
                                                  capture_output=True, text=True, timeout=3)
                            if result.returncode == 0 and f'Id={potential_service}' in result.stdout:
                                return potential_service
                        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                            pass
            
            # Method 5: For daemons ending in 'd', try without the 'd' suffix (with verification)
            if name.endswith('d') and len(name) > 1 and name.lower() not in generic_names:
                base_without_d = name[:-1]
                potential_service = f'{base_without_d}.service'
                try:
                    result = subprocess.run(['systemctl', 'show', potential_service, '-p', 'Id', '--no-pager'], 
                                          capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and f'Id={potential_service}' in result.stdout:
                        return potential_service
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                    pass
            
            return None
        except (FileNotFoundError, PermissionError):
            return None
    
    def _get_systemd_unit_file(self, info):
        """Get systemd unit file information"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
            # Get unit file path
            result = subprocess.run(['systemctl', 'show', service_name, '-p', 'FragmentPath', '--no-pager'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                unit_path = result.stdout.strip().replace('FragmentPath=', '')
                if unit_path and unit_path != '' and os.path.exists(unit_path):
                    # Read unit file content (complete file)
                    try:
                        with open(unit_path, 'r') as f:
                            content = f.read()
                            lines = content.split('\n')
                            return {
                                'path': unit_path,
                                'content_preview': content,
                                'total_lines': len(lines)
                            }
                    except (PermissionError, FileNotFoundError):
                        return {'path': unit_path, 'content_preview': 'Access denied', 'total_lines': 0}
                else:
                    return 'Unit file path not found'
            else:
                return 'Unable to get unit file information'
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return 'systemctl command failed'
    
    def _get_systemd_service_status(self, info):
        """Get systemd service status"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
            # Get service status
            result = subprocess.run(['systemctl', 'status', service_name, '--no-pager', '-l'], 
                                  capture_output=True, text=True, timeout=5)
            
            # Parse status output
            status_info = {
                'raw_output': result.stdout,
                'return_code': result.returncode,
                'active_state': 'unknown',
                'load_state': 'unknown',
                'sub_state': 'unknown'
            }
            
            # Extract key status information
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if 'Active:' in line:
                    status_info['active_state'] = line.split('Active:')[1].strip()
                elif 'Loaded:' in line:
                    status_info['load_state'] = line.split('Loaded:')[1].strip()
            
            return status_info
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return 'systemctl status command failed'
    
    def _get_systemd_dependencies(self, info):
        """Get systemd service dependencies"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
            dependencies = {}
            
            # Get dependencies
            for dep_type in ['list-dependencies', 'list-dependencies --reverse']:
                cmd = ['systemctl'] + dep_type.split() + [service_name, '--no-pager']
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        deps = []
                        for line in result.stdout.split('\n')[1:]:  # Skip first line (service name)
                            line = line.strip()
                            if line and not line.startswith('●') and not line.startswith('└') and not line.startswith('├'):
                                clean_line = line.replace('●', '').replace('└─', '').replace('├─', '').strip()
                                if clean_line:
                                    deps.append(clean_line)
                        
                        key = 'reverse_dependencies' if '--reverse' in dep_type else 'dependencies'
                        dependencies[key] = deps  # Include all dependencies
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    continue
            
            return dependencies
        except FileNotFoundError:
            return 'systemctl command not available'
    
    def _get_systemd_resource_limits(self, info):
        """Get systemd resource limits for the service"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
            # Get resource limit properties
            limit_properties = [
                'MemoryLimit', 'MemoryMax', 'MemoryCurrent', 'CPUQuota', 'CPUShares',
                'TasksMax', 'TasksCurrent', 'LimitNOFILE', 'User', 'Group'
            ]
            
            result = subprocess.run(['systemctl', 'show', service_name] + 
                                  [f'-p{prop}' for prop in limit_properties] + ['--no-pager'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                limits = {}
                for line in result.stdout.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if value and value != '' and value != 'infinity':
                            limits[key] = value
                return limits
            else:
                return 'Unable to get resource limits'
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return 'systemctl command failed'
    
    def _get_systemd_recent_logs(self, info):
        """Get recent systemd journal entries for the service"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
            # Get recent journal entries
            result = subprocess.run(['journalctl', '-u', service_name, '--no-pager', '-n', '10', '--output=short'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                log_entries = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        log_entries.append(line)
                return log_entries
            else:
                return 'No recent logs found or access denied'
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return 'journalctl command failed or not available'
    
    def _get_systemd_cgroup_info(self, info):
        """Get systemd cgroup information"""
        try:
            cgroup_info = {}
            
            # Read cgroup information
            with open(f'/proc/{self.process.pid}/cgroup', 'r') as f:
                cgroup_data = f.read()
                cgroup_info['cgroup_content'] = cgroup_data.strip()
            
            # Extract systemd-specific cgroup paths
            systemd_paths = []
            for line in cgroup_data.split('\n'):
                if 'systemd:' in line or '.service' in line:
                    systemd_paths.append(line.strip())
            cgroup_info['systemd_paths'] = systemd_paths
            
            # Get memory usage from cgroup if available
            try:
                memory_paths = [
                    f'/sys/fs/cgroup/memory/memory.usage_in_bytes',
                    f'/sys/fs/cgroup/memory.current'  # cgroup v2
                ]
                for memory_path in memory_paths:
                    if os.path.exists(memory_path):
                        with open(memory_path, 'r') as f:
                            cgroup_info['memory_usage_bytes'] = f.read().strip()
                        break
            except (FileNotFoundError, PermissionError):
                pass
            
            return cgroup_info
        except (FileNotFoundError, PermissionError):
            return 'Cgroup information not accessible'
    
    def _analyze_redis_process(self, info):
        """Enhanced analysis for Redis processes"""
        analysis = {}
        
        # Parse command line arguments
        if info['cmdline'] == 'Access denied':
            cmdline_args = []
        else:
            cmdline_args = info['cmdline'].split()
        
        # Extract configuration file path from command line
        config_file = None
        for i, arg in enumerate(cmdline_args):
            if arg.endswith('.conf') or (i > 0 and cmdline_args[i-1] in ['redis-server', '/usr/bin/redis-server']):
                if arg.endswith('.conf'):
                    config_file = arg
                    break
        
        analysis['config_file'] = config_file
        analysis['config_settings'] = self._parse_redis_config(config_file)
        analysis['server_type'] = self._identify_redis_type(info)
        analysis['memory_usage'] = self._get_redis_memory_usage()
        analysis['network_config'] = self._get_redis_network_config(info, config_file)
        analysis['persistence_config'] = self._get_redis_persistence_config(config_file)
        analysis['replication_config'] = self._get_redis_replication_config(config_file)
        analysis['cluster_config'] = self._get_redis_cluster_config(info, config_file)
        
        return analysis
    
    def _parse_redis_config(self, config_file):
        """Parse Redis configuration file"""
        if not config_file:
            return 'Using default configuration (no config file specified)'
        
        try:
            config_settings = {}
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(' ', 1)
                        if len(parts) == 2:
                            config_settings[parts[0]] = parts[1]
            return config_settings
        except (IOError, OSError) as e:
            return f'Could not read config file: {e}'
    
    def _identify_redis_type(self, info):
        """Identify type of Redis instance"""
        if 'sentinel' in info['name'].lower() or 'sentinel' in info['cmdline'].lower():
            return 'Redis Sentinel'
        elif 'cluster' in info['cmdline'].lower():
            return 'Redis Cluster Node'
        else:
            return 'Redis Server'
    
    def _get_redis_memory_usage(self):
        """Get Redis memory usage information"""
        try:
            if hasattr(self.process, 'memory_info'):
                mem_info = self.process.memory_info()
                return {
                    'rss_mb': mem_info.rss // 1024 // 1024,
                    'vms_mb': mem_info.vms // 1024 // 1024
                }
        except Exception:
            pass
        return 'Unable to retrieve memory information'
    
    def _get_redis_network_config(self, info, config_file):
        """Get Redis network configuration"""
        network_config = {'port': '6379', 'bind': '127.0.0.1'}  # defaults
        
        # Parse command line arguments
        if info['cmdline'] == 'Access denied':
            cmdline_args = []
        else:
            cmdline_args = info['cmdline'].split()
        
        # Check command line arguments first
        for i, arg in enumerate(cmdline_args):
            if arg.startswith('--port') and i + 1 < len(cmdline_args):
                network_config['port'] = cmdline_args[i + 1]
            elif arg.startswith('--bind') and i + 1 < len(cmdline_args):
                network_config['bind'] = cmdline_args[i + 1]
        
        # Check config file
        if config_file and isinstance(self._parse_redis_config(config_file), dict):
            config_settings = self._parse_redis_config(config_file)
            if 'port' in config_settings:
                network_config['port'] = config_settings['port']
            if 'bind' in config_settings:
                network_config['bind'] = config_settings['bind']
        
        # Most importantly: Check actual network connections to see what Redis is really listening on
        if isinstance(info.get('connections'), list):
            listening_addresses = []
            for conn in info['connections']:
                if conn.get('status') == 'LISTEN':
                    local_addr = conn.get('laddr', '')
                    if ':6379' in local_addr or f":{network_config['port']}" in local_addr:
                        # Extract the IP address part
                        addr_part = local_addr.split(':')[0] if ':' in local_addr else local_addr
                        if addr_part not in listening_addresses:
                            listening_addresses.append(addr_part)
            
            # Determine actual bind configuration from listening addresses
            if listening_addresses:
                if '0.0.0.0' in listening_addresses:
                    network_config['bind'] = '0.0.0.0 (all interfaces)'
                    network_config['actual_bind'] = 'all interfaces'
                elif len(listening_addresses) == 1 and listening_addresses[0] not in ['0.0.0.0', '::']:
                    network_config['bind'] = listening_addresses[0]
                    network_config['actual_bind'] = listening_addresses[0]
                elif len(listening_addresses) > 1:
                    network_config['bind'] = ', '.join(listening_addresses)
                    network_config['actual_bind'] = 'multiple interfaces'
        
        return network_config
    
    def _get_redis_persistence_config(self, config_file):
        """Get Redis persistence configuration"""
        persistence_config = {'rdb_enabled': False, 'aof_enabled': False}
        
        if config_file and isinstance(self._parse_redis_config(config_file), dict):
            config_settings = self._parse_redis_config(config_file)
            
            # Check for RDB snapshots
            for key in config_settings:
                if key.startswith('save'):
                    persistence_config['rdb_enabled'] = True
                    persistence_config['rdb_settings'] = config_settings[key]
                    break
            
            # Check for AOF
            if 'appendonly' in config_settings:
                persistence_config['aof_enabled'] = config_settings['appendonly'] == 'yes'
                if 'appendfsync' in config_settings:
                    persistence_config['aof_sync'] = config_settings['appendfsync']
        
        return persistence_config
    
    def _get_redis_replication_config(self, config_file):
        """Get Redis replication configuration"""
        replication_config = {'is_replica': False}
        
        if config_file and isinstance(self._parse_redis_config(config_file), dict):
            config_settings = self._parse_redis_config(config_file)
            
            if 'replicaof' in config_settings or 'slaveof' in config_settings:
                replication_config['is_replica'] = True
                replication_config['master'] = config_settings.get('replicaof', config_settings.get('slaveof', ''))
        
        return replication_config
    
    def _get_redis_cluster_config(self, info, config_file):
        """Get Redis cluster configuration"""
        cluster_config = {'enabled': False}
        
        if 'cluster' in info['cmdline'].lower():
            cluster_config['enabled'] = True
        
        if config_file and isinstance(self._parse_redis_config(config_file), dict):
            config_settings = self._parse_redis_config(config_file)
            
            if 'cluster-enabled' in config_settings:
                cluster_config['enabled'] = config_settings['cluster-enabled'] == 'yes'
                if 'cluster-config-file' in config_settings:
                    cluster_config['config_file'] = config_settings['cluster-config-file']
                if 'cluster-node-timeout' in config_settings:
                    cluster_config['node_timeout'] = config_settings['cluster-node-timeout']
        
        return cluster_config

    def _analyze_process_launch(self, info):
        """Analyze how a non-systemd process was launched"""
        analysis = {
            'launch_method': 'unknown',
            'parent_info': {},
            'session_info': {},
            'startup_clues': []
        }
        
        try:
            # Get parent process information
            try:
                parent = self.process.parent()
                if parent:
                    analysis['parent_info'] = {
                        'pid': parent.pid,
                        'name': parent.name(),
                        'cmdline': ' '.join(parent.cmdline()) if parent.cmdline() else 'N/A'
                    }
                    
                    # Analyze parent to determine launch method
                    parent_name = parent.name().lower()
                    parent_cmdline = analysis['parent_info']['cmdline'].lower()
                    
                    if parent_name in ['bash', 'sh', 'zsh', 'fish', 'csh', 'tcsh']:
                        analysis['launch_method'] = 'shell'
                        analysis['startup_clues'].append('Started from interactive shell')
                    elif parent_name in ['ssh', 'sshd']:
                        analysis['launch_method'] = 'ssh_session'
                        analysis['startup_clues'].append('Started via SSH session')
                    elif parent_name in ['cron', 'crond']:
                        analysis['launch_method'] = 'cron'
                        analysis['startup_clues'].append('Started by cron scheduler')
                    elif parent_name in ['init', 'systemd']:
                        analysis['launch_method'] = 'init'
                        analysis['startup_clues'].append('Started by init/systemd but not managed as service')
                    elif 'screen' in parent_name or 'tmux' in parent_name:
                        analysis['launch_method'] = 'terminal_multiplexer'
                        analysis['startup_clues'].append(f'Started in {parent_name} session')
                    elif parent.pid == 1:
                        analysis['launch_method'] = 'daemon'
                        analysis['startup_clues'].append('Running as daemon (parent PID 1)')
                    else:
                        analysis['launch_method'] = 'manual'
                        analysis['startup_clues'].append(f'Started by {parent_name}')
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                analysis['parent_info'] = 'Access denied or process not found'
            
            # Check session information
            try:
                analysis['session_info']['session_id'] = os.getsid(self.process.pid)
                analysis['session_info']['process_group'] = os.getpgid(self.process.pid)
            except (OSError, PermissionError):
                analysis['session_info'] = 'Session info not accessible'
            
            # Check for common startup patterns in command line
            cmdline = info['cmdline'].lower()
            if any(pattern in cmdline for pattern in ['nohup', '&', 'daemon']):
                analysis['startup_clues'].append('Command line suggests daemonization')
            
            if 'screen' in cmdline or 'tmux' in cmdline:
                analysis['startup_clues'].append('Started with terminal multiplexer')
            
            # Check for init scripts or rc files
            if '/etc/init.d/' in cmdline or 'rc.local' in cmdline:
                analysis['launch_method'] = 'init_script'
                analysis['startup_clues'].append('Started by init script')
            
            # Check working directory for clues
            try:
                cwd = self.process.cwd()
                if cwd in ['/tmp', '/var/tmp']:
                    analysis['startup_clues'].append('Running from temporary directory')
                elif cwd == '/':
                    analysis['startup_clues'].append('Running from root directory (typical for daemons)')
                elif '/home/' in cwd:
                    analysis['startup_clues'].append('Running from user home directory')
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return analysis
        except Exception as e:
            return f'Error analyzing launch method: {str(e)}'
    
    def _generate_systemd_suggestion(self, info):
        """Generate systemd service unit file suggestion for non-systemd process"""
        try:
            # Extract basic information
            process_name = info['name']
            cmdline = info['cmdline']
            cwd = info.get('cwd', '/opt')
            
            if cmdline == 'Access denied':
                return 'Cannot generate systemd suggestion due to access restrictions'
            
            # Parse command line to get executable and arguments
            cmd_parts = cmdline.split() if isinstance(cmdline, str) else []
            if not cmd_parts:
                return 'Cannot parse command line for systemd suggestion'
            
            executable = cmd_parts[0]
            args = ' '.join(cmd_parts[1:]) if len(cmd_parts) > 1 else ''
            
            # Determine appropriate service type based on process characteristics
            service_type = 'simple'  # Default
            restart_policy = 'on-failure'
            
            # Analyze process to suggest better service configuration
            launch_analysis = info.get('launch_analysis', {})
            if isinstance(launch_analysis, dict):
                launch_method = launch_analysis.get('launch_method', 'unknown')
                if launch_method == 'daemon':
                    service_type = 'forking'
                elif launch_method in ['cron', 'init_script']:
                    restart_policy = 'always'
            
            # Check if process uses network (suggest After=network.target)
            network_deps = ''
            if isinstance(info.get('connections'), list) and info['connections']:
                network_deps = 'After=network.target\nWants=network.target\n'
            
            # Determine user (try to avoid running as root if possible)
            user_config = ''
            try:
                username = self.process.username()
                if username and username != 'root':
                    user_config = f'User={username}\n'
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # Generate the systemd unit file
            service_file = f"""# Suggested systemd service unit file for {process_name}
# Save as: /etc/systemd/system/{process_name}.service
# Enable with: sudo systemctl enable {process_name}.service
# Start with: sudo systemctl start {process_name}.service

[Unit]
Description={process_name.title()} Service
{network_deps}
[Service]
Type={service_type}
{user_config}ExecStart={executable}{' ' + args if args else ''}
WorkingDirectory={cwd if cwd != 'Access denied' else '/opt'}
Restart={restart_policy}
RestartSec=5

# Security settings (adjust as needed)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={cwd if cwd != 'Access denied' else '/opt'}

[Install]
WantedBy=multi-user.target"""

            # Add management commands
            management_commands = f"""

# Management commands:
# sudo systemctl daemon-reload          # Reload systemd configuration
# sudo systemctl enable {process_name}  # Enable service to start at boot
# sudo systemctl start {process_name}   # Start the service
# sudo systemctl stop {process_name}    # Stop the service
# sudo systemctl restart {process_name} # Restart the service
# sudo systemctl status {process_name}  # Check service status
# journalctl -u {process_name} -f       # View service logs"""

            return {
                'service_file': service_file,
                'management_commands': management_commands,
                'service_name': f'{process_name}.service'
            }
            
        except Exception as e:
            return f'Error generating systemd suggestion: {str(e)}'

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
    
    # Shared Libraries Analysis
    if isinstance(info['shared_libraries'], dict):
        libs = info['shared_libraries']
        output.write(f"\n{'='*50}\n")
        output.write("SHARED LIBRARIES ANALYSIS\n")
        output.write(f"{'='*50}\n")
        output.write(f"Total Memory Mappings: {libs['total_count']}\n")
        output.write(f"Unique Library Directories: {len(libs['unique_directories'])}\n")
        
        # System Libraries
        if libs['system_libraries']:
            output.write(f"\nSystem Libraries ({len(libs['system_libraries'])}):\n")
            
            # Group by subcategory
            by_category = {}
            for lib in libs['system_libraries']:
                subcat = lib.get('subcategory', 'other')
                if subcat not in by_category:
                    by_category[subcat] = []
                by_category[subcat].append(lib)
            
            for category, category_libs in by_category.items():
                if category_libs:
                    output.write(f"\n  {category.replace('_', ' ').title()} Libraries ({len(category_libs)}):\n")
                    for lib in category_libs:  # Show all libraries
                        size_mb = lib['rss'] / (1024 * 1024)
                        output.write(f"    {os.path.basename(lib['path'])} ({size_mb:.1f} MB)\n")
                        output.write(f"      Process Path: {lib['path']}\n")
                        if lib['real_path'] and lib['real_path'] != lib['path']:
                            output.write(f"      Real Path:    {lib['real_path']}\n")
                        elif lib['real_path']:
                            output.write(f"      Real Path:    {lib['real_path']}\n")
                        output.write("\n")
        
        # Language-Specific Libraries
        if libs['language_specific']:
            output.write(f"\nLanguage-Specific Libraries ({len(libs['language_specific'])}):\n")
            
            # Group by language
            by_language = {}
            for lib in libs['language_specific']:
                lang = lib.get('language', 'unknown')
                if lang not in by_language:
                    by_language[lang] = []
                by_language[lang].append(lib)
            
            for language, lang_libs in by_language.items():
                if lang_libs:
                    output.write(f"\n  {language.title()} Libraries ({len(lang_libs)}):\n")
                    for lib in lang_libs[:3]:  # Show top 3 by memory usage
                        size_mb = lib['rss'] / (1024 * 1024)
                        output.write(f"    {os.path.basename(lib['path'])} ({size_mb:.1f} MB)\n")
                        output.write(f"      Process Path: {lib['path']}\n")
                        if lib['real_path'] and lib['real_path'] != lib['path']:
                            output.write(f"      Real Path:    {lib['real_path']}\n")
                        output.write("\n")
                    if len(lang_libs) > 3:
                        output.write(f"    ... and {len(lang_libs) - 3} more\n")
        
        # User/Application Libraries
        if libs['user_libraries']:
            output.write(f"\nUser/Application Libraries ({len(libs['user_libraries'])}):\n")
            for lib in libs['user_libraries'][:5]:  # Show top 5 by memory usage
                size_mb = lib['rss'] / (1024 * 1024)
                output.write(f"  {os.path.basename(lib['path'])} ({size_mb:.1f} MB)\n")
                output.write(f"    Process Path: {lib['path']}\n")
                if lib['real_path'] and lib['real_path'] != lib['path']:
                    output.write(f"    Real Path:    {lib['real_path']}\n")
                elif lib['real_path']:
                    output.write(f"    Real Path:    {lib['real_path']}\n")
                output.write("\n")
            if len(libs['user_libraries']) > 5:
                output.write(f"  ... and {len(libs['user_libraries']) - 5} more\n")
        
        # Library Directory Summary
        if libs['unique_directories']:
            output.write(f"\nLibrary Directories ({len(libs['unique_directories'])}):\n")
            for directory in libs['unique_directories'][:10]:  # Show first 10 directories
                output.write(f"  {directory}\n")
            if len(libs['unique_directories']) > 10:
                output.write(f"  ... and {len(libs['unique_directories']) - 10} more\n")
    
    elif isinstance(info['shared_libraries'], str):
        output.write(f"\nShared Libraries: {info['shared_libraries']}\n")
    
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
    
    # Systemd-specific analysis
    if 'systemd_analysis' in info:
        systemd = info['systemd_analysis']
        output.write(f"\n{'='*50}\n")
        output.write("SYSTEMD SERVICE ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        # Service Information
        if isinstance(systemd['service_info'], dict):
            output.write("Service Information:\n")
            key_props = ['Id', 'Description', 'Type', 'ExecStart', 'User', 'Group', 'MainPID']
            for prop in key_props:
                if prop in systemd['service_info']:
                    output.write(f"  {prop}: {systemd['service_info'][prop]}\n")
        elif isinstance(systemd['service_info'], str):
            output.write(f"Service Information: {systemd['service_info']}\n")
        
        # Service Status
        if isinstance(systemd['service_status'], dict):
            output.write(f"\nService Status:\n")
            output.write(f"  Active State: {systemd['service_status'].get('active_state', 'unknown')}\n")
            output.write(f"  Load State: {systemd['service_status'].get('load_state', 'unknown')}\n")
        elif isinstance(systemd['service_status'], str):
            output.write(f"\nService Status: {systemd['service_status']}\n")
        
        # Unit File Information
        if isinstance(systemd['unit_file'], dict):
            output.write(f"\nUnit File:\n")
            output.write(f"  Path: {systemd['unit_file'].get('path', 'unknown')}\n")
            if 'content_preview' in systemd['unit_file'] and systemd['unit_file']['content_preview'] != 'Access denied':
                output.write("  Content:\n")
                lines = systemd['unit_file']['content_preview'].split('\n')
                for line in lines:
                    output.write(f"    {line}\n")
        elif isinstance(systemd['unit_file'], str):
            output.write(f"\nUnit File: {systemd['unit_file']}\n")
        
        # Dependencies
        if isinstance(systemd['dependencies'], dict):
            if systemd['dependencies'].get('dependencies'):
                output.write(f"\nDependencies ({len(systemd['dependencies']['dependencies'])}):\n")
                for dep in systemd['dependencies']['dependencies']:
                    output.write(f"  {dep}\n")
            
            if systemd['dependencies'].get('reverse_dependencies'):
                output.write(f"\nDependent Services ({len(systemd['dependencies']['reverse_dependencies'])}):\n")
                for dep in systemd['dependencies']['reverse_dependencies']:
                    output.write(f"  {dep}\n")
        elif isinstance(systemd['dependencies'], str):
            output.write(f"\nDependencies: {systemd['dependencies']}\n")
        
        # Resource Limits
        if isinstance(systemd['resource_limits'], dict) and systemd['resource_limits']:
            output.write(f"\nResource Limits:\n")
            for key, value in systemd['resource_limits'].items():
                output.write(f"  {key}: {value}\n")
        elif isinstance(systemd['resource_limits'], str):
            output.write(f"\nResource Limits: {systemd['resource_limits']}\n")
        
        # Recent Logs
        if isinstance(systemd['recent_logs'], list) and systemd['recent_logs']:
            output.write(f"\nRecent Journal Entries ({len(systemd['recent_logs'])}):\n")
            for log_entry in systemd['recent_logs'][:5]:
                # Truncate very long log entries
                truncated_entry = log_entry[:100] + '...' if len(log_entry) > 100 else log_entry
                output.write(f"  {truncated_entry}\n")
            if len(systemd['recent_logs']) > 5:
                output.write(f"  ... and {len(systemd['recent_logs']) - 5} more entries\n")
        elif isinstance(systemd['recent_logs'], str):
            output.write(f"\nRecent Logs: {systemd['recent_logs']}\n")
        
        # Cgroup Information
        if isinstance(systemd['cgroup_info'], dict):
            if systemd['cgroup_info'].get('systemd_paths'):
                output.write(f"\nSystemd Cgroup Paths:\n")
                for path in systemd['cgroup_info']['systemd_paths'][:3]:
                    output.write(f"  {path}\n")
            if systemd['cgroup_info'].get('memory_usage_bytes'):
                try:
                    memory_mb = int(systemd['cgroup_info']['memory_usage_bytes']) / (1024 * 1024)
                    output.write(f"\nCgroup Memory Usage: {memory_mb:.1f} MB\n")
                except (ValueError, TypeError):
                    output.write(f"\nCgroup Memory Usage: {systemd['cgroup_info']['memory_usage_bytes']}\n")
        elif isinstance(systemd['cgroup_info'], str):
            output.write(f"\nCgroup Information: {systemd['cgroup_info']}\n")
    
    # Launch analysis for non-systemd processes
    if 'launch_analysis' in info:
        launch = info['launch_analysis']
        output.write(f"\n{'='*50}\n")
        output.write("PROCESS LAUNCH ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        if isinstance(launch, dict):
            output.write(f"Launch Method: {launch.get('launch_method', 'unknown')}\n")
            
            if isinstance(launch.get('parent_info'), dict):
                parent = launch['parent_info']
                output.write(f"\nParent Process:\n")
                output.write(f"  PID: {parent.get('pid', 'unknown')}\n")
                output.write(f"  Name: {parent.get('name', 'unknown')}\n")
                output.write(f"  Command: {parent.get('cmdline', 'unknown')}\n")
            elif isinstance(launch.get('parent_info'), str):
                output.write(f"\nParent Process: {launch['parent_info']}\n")
            
            if isinstance(launch.get('session_info'), dict):
                session = launch['session_info']
                output.write(f"\nSession Information:\n")
                output.write(f"  Session ID: {session.get('session_id', 'unknown')}\n")
                output.write(f"  Process Group: {session.get('process_group', 'unknown')}\n")
            elif isinstance(launch.get('session_info'), str):
                output.write(f"\nSession Information: {launch['session_info']}\n")
            
            if launch.get('startup_clues'):
                output.write(f"\nStartup Clues:\n")
                for clue in launch['startup_clues']:
                    output.write(f"  • {clue}\n")
        else:
            output.write(f"Launch Analysis: {launch}\n")
    
    # Systemd migration suggestion for non-systemd processes
    if 'systemd_suggestion' in info:
        suggestion = info['systemd_suggestion']
        output.write(f"\n{'='*50}\n")
        output.write("SYSTEMD MIGRATION SUGGESTION\n")
        output.write(f"{'='*50}\n")
        
        if isinstance(suggestion, dict):
            if 'service_file' in suggestion:
                output.write("Suggested systemd service unit file:\n\n")
                output.write(suggestion['service_file'])
                output.write("\n")
            
            if 'management_commands' in suggestion:
                output.write(suggestion['management_commands'])
                output.write("\n")
        elif isinstance(suggestion, str):
            output.write(f"Systemd Suggestion: {suggestion}\n")
    
    # Redis-specific analysis
    if 'redis_analysis' in info:
        redis = info['redis_analysis']
        output.write(f"\n{'='*50}\n")
        output.write("REDIS ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        output.write(f"Server Type: {redis['server_type']}\n")
        
        # Configuration file
        if redis['config_file']:
            output.write(f"\nConfiguration File: {redis['config_file']}\n")
        else:
            output.write(f"\nConfiguration: Using default settings (no config file)\n")
        
        # Configuration settings
        if isinstance(redis['config_settings'], dict):
            if redis['config_settings']:
                output.write(f"\nKey Configuration Settings:\n")
                important_settings = ['port', 'bind', 'maxmemory', 'maxmemory-policy', 'save', 'appendonly', 'dir', 'logfile']
                for setting in important_settings:
                    if setting in redis['config_settings']:
                        output.write(f"  {setting}: {redis['config_settings'][setting]}\n")
        elif isinstance(redis['config_settings'], str):
            output.write(f"\nConfiguration Settings: {redis['config_settings']}\n")
        
        # Network configuration
        if isinstance(redis['network_config'], dict):
            output.write(f"\nNetwork Configuration:\n")
            output.write(f"  Port: {redis['network_config'].get('port', '6379')}\n")
            output.write(f"  Bind Address: {redis['network_config'].get('bind', '127.0.0.1')}\n")
        
        # Memory usage
        if isinstance(redis['memory_usage'], dict):
            output.write(f"\nMemory Usage:\n")
            output.write(f"  RSS: {redis['memory_usage']['rss_mb']} MB\n")
            output.write(f"  VMS: {redis['memory_usage']['vms_mb']} MB\n")
        elif isinstance(redis['memory_usage'], str):
            output.write(f"\nMemory Usage: {redis['memory_usage']}\n")
        
        # Persistence configuration
        if isinstance(redis['persistence_config'], dict):
            output.write(f"\nPersistence Configuration:\n")
            output.write(f"  RDB Snapshots: {'Enabled' if redis['persistence_config']['rdb_enabled'] else 'Disabled'}\n")
            if redis['persistence_config']['rdb_enabled'] and 'rdb_settings' in redis['persistence_config']:
                output.write(f"    Settings: {redis['persistence_config']['rdb_settings']}\n")
            output.write(f"  AOF (Append Only File): {'Enabled' if redis['persistence_config']['aof_enabled'] else 'Disabled'}\n")
            if redis['persistence_config']['aof_enabled'] and 'aof_sync' in redis['persistence_config']:
                output.write(f"    Sync Policy: {redis['persistence_config']['aof_sync']}\n")
        
        # Replication configuration
        if isinstance(redis['replication_config'], dict):
            if redis['replication_config']['is_replica']:
                output.write(f"\nReplication Configuration:\n")
                output.write(f"  Role: Replica (Slave)\n")
                output.write(f"  Master: {redis['replication_config']['master']}\n")
            else:
                output.write(f"\nReplication Configuration:\n")
                output.write(f"  Role: Master\n")
        
        # Cluster configuration
        if isinstance(redis['cluster_config'], dict):
            output.write(f"\nCluster Configuration:\n")
            output.write(f"  Cluster Mode: {'Enabled' if redis['cluster_config']['enabled'] else 'Disabled'}\n")
            if redis['cluster_config']['enabled']:
                if 'config_file' in redis['cluster_config']:
                    output.write(f"  Cluster Config File: {redis['cluster_config']['config_file']}\n")
                if 'node_timeout' in redis['cluster_config']:
                    output.write(f"  Node Timeout: {redis['cluster_config']['node_timeout']}\n")
    
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
    
    # Detect if we're in an interactive terminal session
    is_interactive_terminal = sys.stdin.isatty() and sys.stdout.isatty()
    
    # Handle missing PID - automatically go interactive if in terminal
    if args.pid is None and not args.non_interactive:
        if is_interactive_terminal:
            # Automatically start interactive mode in terminal sessions
            print("No PID specified. Starting interactive process selection...")
            args.pid = select_process_interactive()
        else:
            # In non-terminal environments, still prompt
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
                # Preserve the selected PID when escalating
                escalated_args = sys.argv.copy()
                if args.pid and str(args.pid) not in escalated_args:
                    escalated_args.append(str(args.pid))
                subprocess.run(['sudo', sys.executable] + escalated_args, check=True)
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
        
        # Automatically enable enhanced analysis for Redis processes
        if is_redis_process(info):
            enhanced = True
            if not args.non_interactive:
                print(f"\nDetected Redis server process. Including Redis analysis automatically.")
        
        # Inform user about automatic systemd analysis inclusion
        if is_systemd_managed_process(info) and not args.non_interactive:
            service_name = analyzer._detect_systemd_service_name(info)
            service_display = f" ({service_name})" if service_name else ""
            print(f"\nDetected systemd-managed process{service_display}. Including systemd analysis automatically.")
        
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