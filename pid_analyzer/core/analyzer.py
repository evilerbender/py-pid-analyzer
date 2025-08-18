"""
Main process analyzer class.
"""

import os
import subprocess
from typing import Dict, Any, Optional, Union

try:
    import psutil
except ImportError:
    psutil = None

from ..models.process_info import ProcessInfo, AnalysisResult
from ..core.process_detection import is_systemd_managed_process


class ProcessAnalyzer:
    """Main process analyzer class."""
    
    def __init__(self, pid: int):
        if not psutil:
            raise ImportError("psutil is required for process analysis")
        
        try:
            self.process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            raise ValueError(f"Process {pid} not found")
    
    def analyze(self, enhanced: bool = False) -> AnalysisResult:
        """Analyze process and return detailed information."""
        # Get basic process information
        info = self._get_basic_info()
        
        # Create ProcessInfo object
        process_info = ProcessInfo(
            pid=info['pid'],
            name=info['name'],
            status=info['status'],
            cmdline=info['cmdline'],
            exe=info['exe'],
            cwd=info['cwd'],
            environ=info['environ'],
            connections=info['connections'],
            open_files=info['open_files'],
            memory_maps=info['memory_maps'],
            shared_libraries=info['shared_libraries']
        )
        
        # Initialize result
        result = AnalysisResult(process_info=process_info)
        
        # Run specialized analyses
        if enhanced:
            # Import analyzers dynamically to avoid circular imports
            from ..core.process_detection import (
                is_java_process, is_webserver_process, is_redis_process
            )
            
            if is_java_process(info):
                try:
                    from ..analyzers.java import JavaAnalyzer
                    java_analyzer = JavaAnalyzer(self.process)
                    result.java_analysis = java_analyzer.analyze(info)
                except ImportError:
                    pass
            
            if is_webserver_process(info):
                try:
                    from ..analyzers.webserver import WebServerAnalyzer
                    webserver_analyzer = WebServerAnalyzer(self.process)
                    result.webserver_analysis = webserver_analyzer.analyze(info)
                except ImportError:
                    pass
            
            if is_redis_process(info):
                try:
                    from ..analyzers.redis import RedisAnalyzer
                    redis_analyzer = RedisAnalyzer(self.process)
                    result.redis_analysis = redis_analyzer.analyze(info)
                except ImportError:
                    pass
        
        # Always include systemd analysis for systemd-managed processes
        if is_systemd_managed_process(info):
            try:
                from ..analyzers.systemd import SystemdAnalyzer
                systemd_analyzer = SystemdAnalyzer(self.process)
                result.systemd_analysis = systemd_analyzer.analyze(info)
            except ImportError:
                pass
        else:
            # For non-systemd processes, analyze launch method and suggest systemd migration
            result.launch_analysis = self._analyze_process_launch(info)
            result.systemd_suggestion = self._generate_systemd_suggestion(info)
        
        return result
    
    def _get_basic_info(self) -> Dict[str, Any]:
        """Get basic process information."""
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
        
        return info
    
    def _get_memory_maps(self) -> Union[list, str]:
        """Get shared libraries and memory mappings."""
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
    
    def _get_open_files(self) -> Union[list, str]:
        """Get open file descriptors."""
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
    
    def _get_connections(self) -> Union[list, str]:
        """Get network connections."""
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
    
    def _get_shared_libraries(self) -> Union[Dict[str, Any], str]:
        """Get shared libraries used by the process."""
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
    
    def _analyze_process_launch(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze how a non-systemd process was launched."""
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
            
            return analysis
        except Exception as e:
            return f'Error analyzing launch method: {str(e)}'
    
    def _generate_systemd_suggestion(self, info: Dict[str, Any]) -> Union[Dict[str, str], str]:
        """Generate systemd service unit file suggestion for non-systemd process."""
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
After=network.target

[Service]
Type=simple
{user_config}ExecStart={executable}{' ' + args if args else ''}
WorkingDirectory={cwd if cwd != 'Access denied' else '/opt'}
Restart=on-failure
RestartSec=5

# Security settings (adjust as needed)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

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
