"""
Redis analyzer.
"""

from typing import Dict, Any, Optional

from .base import BaseAnalyzer
from ..core.process_detection import is_redis_process


class RedisAnalyzer(BaseAnalyzer):
    """Analyzer for Redis servers."""
    
    def detect(self, info: Dict[str, Any]) -> bool:
        """Detect if this is a Redis process."""
        return is_redis_process(info)
    
    def analyze(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform Redis-specific analysis."""
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
    
    def get_analysis_name(self) -> str:
        """Get the name of this analysis type."""
        return "redis_analysis"
    
    def _parse_redis_config(self, config_file: Optional[str]) -> Dict[str, str]:
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
    
    def _identify_redis_type(self, info: Dict[str, Any]) -> str:
        """Identify type of Redis instance"""
        if 'sentinel' in info['name'].lower() or 'sentinel' in info['cmdline'].lower():
            return 'Redis Sentinel'
        elif 'cluster' in info['cmdline'].lower():
            return 'Redis Cluster Node'
        else:
            return 'Redis Server'
    
    def _get_redis_memory_usage(self) -> Dict[str, int]:
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
    
    def _get_redis_network_config(self, info: Dict[str, Any], config_file: Optional[str]) -> Dict[str, str]:
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
        
        # Check actual network connections
        if isinstance(info.get('connections'), list):
            listening_addresses = []
            for conn in info['connections']:
                if conn.get('status') == 'LISTEN':
                    local_addr = conn.get('laddr', '')
                    if ':6379' in local_addr or f":{network_config['port']}" in local_addr:
                        addr_part = local_addr.split(':')[0] if ':' in local_addr else local_addr
                        if addr_part not in listening_addresses:
                            listening_addresses.append(addr_part)
            
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
    
    def _get_redis_persistence_config(self, config_file: Optional[str]) -> Dict[str, Any]:
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
    
    def _get_redis_replication_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Get Redis replication configuration"""
        replication_config = {'is_replica': False}
        
        if config_file and isinstance(self._parse_redis_config(config_file), dict):
            config_settings = self._parse_redis_config(config_file)
            
            if 'replicaof' in config_settings or 'slaveof' in config_settings:
                replication_config['is_replica'] = True
                replication_config['master'] = config_settings.get('replicaof', config_settings.get('slaveof', ''))
        
        return replication_config
    
    def _get_redis_cluster_config(self, info: Dict[str, Any], config_file: Optional[str]) -> Dict[str, Any]:
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
