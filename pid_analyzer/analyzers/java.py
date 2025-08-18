"""
Java application analyzer.
"""

import os
from typing import Dict, Any, List

from .base import BaseAnalyzer
from ..core.process_detection import is_java_process


class JavaAnalyzer(BaseAnalyzer):
    """Analyzer for Java applications."""
    
    def detect(self, info: Dict[str, Any]) -> bool:
        """Detect if this is a Java process."""
        return is_java_process(info)
    
    def analyze(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Java-specific analysis."""
        analysis = {}
        analysis['jvm_config'] = self._parse_jvm_args(info)
        analysis['app_type'] = self._identify_java_app_type(info)
        analysis['jar_files'] = self._get_jar_files(info)
        analysis['db_connections'] = self._analyze_db_connections(info)
        analysis['config_files'] = self._get_config_files(info)
        analysis['security'] = self._analyze_security_settings(info)
        return analysis
    
    def get_analysis_name(self) -> str:
        """Get the name of this analysis type."""
        return "java_analysis"
    
    def _parse_jvm_args(self, info: Dict[str, Any]) -> Dict[str, Any]:
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
    
    def _identify_java_app_type(self, info: Dict[str, Any]) -> str:
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
    
    def _get_jar_files(self, info: Dict[str, Any]) -> List[str]:
        """Get loaded JAR files from memory maps"""
        jar_files = []
        if isinstance(info['memory_maps'], list):
            for mmap in info['memory_maps']:
                if mmap['path'].endswith('.jar'):
                    jar_files.append(mmap['path'])
        return jar_files
    
    def _analyze_db_connections(self, info: Dict[str, Any]) -> Dict[str, Any]:
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
    
    def _get_config_files(self, info: Dict[str, Any]) -> List[str]:
        """Get configuration files"""
        config_files = []
        if isinstance(info['open_files'], list):
            for f in info['open_files']:
                path = f['path']
                if any(ext in path for ext in ['.xml', '.properties', '.yml', '.yaml', '.conf']):
                    config_files.append(path)
        return config_files
    
    def _analyze_security_settings(self, info: Dict[str, Any]) -> Dict[str, Any]:
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
