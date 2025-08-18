"""
Systemd service analyzer.
"""

import os
import subprocess
from typing import Dict, Any, Optional

from .base import BaseAnalyzer
from ..core.process_detection import is_systemd_managed_process


class SystemdAnalyzer(BaseAnalyzer):
    """Analyzer for systemd-managed processes."""
    
    def detect(self, info: Dict[str, Any]) -> bool:
        """Detect if this is a systemd-managed process."""
        return is_systemd_managed_process(info)
    
    def analyze(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform systemd-specific analysis."""
        analysis = {}
        analysis['service_info'] = self._get_systemd_service_info(info)
        analysis['unit_file'] = self._get_systemd_unit_file(info)
        analysis['service_status'] = self._get_systemd_service_status(info)
        analysis['dependencies'] = self._get_systemd_dependencies(info)
        analysis['resource_limits'] = self._get_systemd_resource_limits(info)
        analysis['recent_logs'] = self._get_systemd_recent_logs(info)
        analysis['cgroup_info'] = self._get_systemd_cgroup_info(info)
        return analysis
    
    def get_analysis_name(self) -> str:
        """Get the name of this analysis type."""
        return "systemd_analysis"
    
    def _get_systemd_service_info(self, info: Dict[str, Any]) -> Dict[str, str]:
        """Get basic systemd service information"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Unable to determine service name'
            
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
    
    def _detect_systemd_service_name(self, info: Dict[str, Any]) -> Optional[str]:
        """Detect systemd service name from various sources"""
        try:
            # Method 1: Check cgroup information (most reliable)
            with open(f'/proc/{self.process.pid}/cgroup', 'r') as f:
                cgroup_data = f.read()
                for line in cgroup_data.split('\n'):
                    if '.service' in line:
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
            
            # Method 2: Try using the process name directly
            name = info['name']
            generic_names = ['python3', 'python', 'bash', 'sh', 'zsh', 'fish', 'node', 'java', 'perl', 'ruby']
            if name.lower() not in generic_names:
                potential_service = f'{name}.service'
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
    
    def _get_systemd_unit_file(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Get systemd unit file information"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
            result = subprocess.run(['systemctl', 'show', service_name, '-p', 'FragmentPath', '--no-pager'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                unit_path = result.stdout.strip().replace('FragmentPath=', '')
                if unit_path and unit_path != '' and os.path.exists(unit_path):
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
    
    def _get_systemd_service_status(self, info: Dict[str, Any]) -> Dict[str, str]:
        """Get systemd service status"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
            result = subprocess.run(['systemctl', 'status', service_name, '--no-pager', '-l'], 
                                  capture_output=True, text=True, timeout=5)
            
            status_info = {
                'raw_output': result.stdout,
                'return_code': result.returncode,
                'active_state': 'unknown',
                'load_state': 'unknown',
                'sub_state': 'unknown'
            }
            
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
    
    def _get_systemd_dependencies(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Get systemd service dependencies"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
            dependencies = {}
            
            for dep_type in ['list-dependencies', 'list-dependencies --reverse']:
                cmd = ['systemctl'] + dep_type.split() + [service_name, '--no-pager']
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        deps = []
                        for line in result.stdout.split('\n')[1:]:
                            line = line.strip()
                            if line and not line.startswith('●') and not line.startswith('└') and not line.startswith('├'):
                                clean_line = line.replace('●', '').replace('└─', '').replace('├─', '').strip()
                                if clean_line:
                                    deps.append(clean_line)
                        
                        key = 'reverse_dependencies' if '--reverse' in dep_type else 'dependencies'
                        dependencies[key] = deps
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    continue
            
            return dependencies
        except FileNotFoundError:
            return 'systemctl command not available'
    
    def _get_systemd_resource_limits(self, info: Dict[str, Any]) -> Dict[str, str]:
        """Get systemd resource limits"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
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
    
    def _get_systemd_recent_logs(self, info: Dict[str, Any]) -> Any:
        """Get recent systemd journal entries"""
        try:
            service_name = self._detect_systemd_service_name(info)
            if not service_name:
                return 'Service name not detected'
            
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
    
    def _get_systemd_cgroup_info(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Get systemd cgroup information"""
        try:
            cgroup_info = {}
            
            with open(f'/proc/{self.process.pid}/cgroup', 'r') as f:
                cgroup_data = f.read()
                cgroup_info['cgroup_content'] = cgroup_data.strip()
            
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
