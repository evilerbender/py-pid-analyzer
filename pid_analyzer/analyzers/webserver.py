"""
Web server analyzer.
"""

from typing import Dict, Any, List

from .base import BaseAnalyzer
from ..core.process_detection import is_webserver_process


class WebServerAnalyzer(BaseAnalyzer):
    """Analyzer for web servers and reverse proxies."""
    
    def detect(self, info: Dict[str, Any]) -> bool:
        """Detect if this is a web server process."""
        return is_webserver_process(info)
    
    def analyze(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform web server-specific analysis."""
        analysis = {}
        analysis['server_type'] = self._identify_webserver_type(info)
        analysis['config_files'] = self._get_webserver_configs(info)
        analysis['virtual_hosts'] = self._analyze_virtual_hosts(info)
        analysis['ssl_config'] = self._analyze_webserver_ssl(info)
        analysis['modules'] = self._get_webserver_modules(info)
        analysis['log_files'] = self._get_webserver_logs(info)
        return analysis
    
    def get_analysis_name(self) -> str:
        """Get the name of this analysis type."""
        return "webserver_analysis"
    
    def _identify_webserver_type(self, info: Dict[str, Any]) -> str:
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
    
    def _get_webserver_configs(self, info: Dict[str, Any]) -> List[str]:
        """Get web server configuration files"""
        config_files = []
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(config in path for config in ['httpd.conf', 'apache2.conf', 'nginx.conf', 'haproxy.cfg', 'sites-enabled', 'sites-available', 'conf.d']):
                    config_files.append(path)
        return config_files
    
    def _analyze_virtual_hosts(self, info: Dict[str, Any]) -> List[str]:
        """Analyze virtual host configurations"""
        vhosts = []
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(vhost in path for vhost in ['sites-enabled', 'sites-available', 'vhosts', 'conf.d']):
                    vhosts.append(path)
        return vhosts
    
    def _analyze_webserver_ssl(self, info: Dict[str, Any]) -> Dict[str, Any]:
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
    
    def _get_webserver_modules(self, info: Dict[str, Any]) -> List[str]:
        """Get loaded web server modules"""
        modules = []
        if isinstance(info['memory_maps'], list):
            for mmap in info['memory_maps']:
                path = mmap['path']
                if any(mod in path for mod in ['mod_', 'modules/', 'nginx/modules']):
                    modules.append(path)
        return modules
    
    def _get_webserver_logs(self, info: Dict[str, Any]) -> List[str]:
        """Get web server log files"""
        log_files = []
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(log in path for log in ['access.log', 'error.log', 'access_log', 'error_log', '/var/log/']):
                    log_files.append(path)
        return log_files
