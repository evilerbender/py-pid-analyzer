"""
Configuration management for the process analyzer.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class Config:
    """Configuration manager."""
    
    def __init__(self):
        self._config = self._load_default_config()
        self._load_user_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration."""
        return {
            'analyzers': {
                'java': {
                    'detection_patterns': {
                        'cmdline': ['catalina', 'tomcat', 'spring', 'jetty', '.jar', 'wildfly', 'jboss'],
                        'env_vars': ['CATALINA_HOME', 'JAVA_HOME']
                    },
                    'jvm_args': {
                        'heap_indicators': ['-Xmx', '-Xms'],
                        'gc_indicators': ['-XX:']
                    }
                },
                'webserver': {
                    'detection_patterns': {
                        'names': ['httpd', 'apache2', 'nginx', 'haproxy'],
                        'cmdline': ['httpd', 'apache2', 'nginx', 'haproxy']
                    },
                    'config_files': ['httpd.conf', 'apache2.conf', 'nginx.conf', 'haproxy.cfg']
                },
                'redis': {
                    'detection_patterns': {
                        'names': ['redis-server', 'redis-sentinel'],
                        'cmdline': ['redis-server', 'redis-sentinel', 'redis-cluster', 'redis.conf']
                    },
                    'default_port': 6379,
                    'config_files': ['redis.conf']
                }
            },
            'output': {
                'default_format': 'text',
                'page_size': 50,
                'max_items_display': 5
            },
            'ui': {
                'default_filter': 'user',
                'default_sort': 'pid',
                'page_size': 50
            }
        }
    
    def _load_user_config(self):
        """Load user configuration file if it exists."""
        if not HAS_YAML:
            return  # Skip YAML config loading if PyYAML not available
        
        config_paths = [
            Path.home() / '.config' / 'pid-analyzer' / 'config.yaml',
            Path.home() / '.pid-analyzer.yaml',
            Path.cwd() / 'pid-analyzer.yaml'
        ]
        
        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        user_config = yaml.safe_load(f)
                        self._merge_config(user_config)
                    break
                except (yaml.YAMLError, IOError):
                    continue
    
    def _merge_config(self, user_config: Dict[str, Any]):
        """Merge user configuration with default configuration."""
        def deep_merge(default: Dict, user: Dict) -> Dict:
            result = default.copy()
            for key, value in user.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result
        
        self._config = deep_merge(self._config, user_config)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)."""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_analyzer_config(self, analyzer_name: str) -> Dict[str, Any]:
        """Get configuration for a specific analyzer."""
        return self.get(f'analyzers.{analyzer_name}', {})
    
    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration."""
        return self.get('output', {})
    
    def get_ui_config(self) -> Dict[str, Any]:
        """Get UI configuration."""
        return self.get('ui', {})


# Global configuration instance
config = Config()
