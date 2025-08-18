"""
Data models for process information and analysis results.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union


@dataclass
class ProcessInfo:
    """Basic process information."""
    pid: int
    name: str
    status: str
    cmdline: str
    exe: str
    cwd: str
    environ: Union[Dict[str, str], str]
    connections: Union[List[Dict[str, Any]], str]
    open_files: Union[List[Dict[str, Any]], str]
    memory_maps: Union[List[Dict[str, Any]], str]
    shared_libraries: Union[Dict[str, Any], str] = field(default_factory=dict)


@dataclass
class JavaAnalysis:
    """Java-specific analysis results."""
    app_type: str
    jvm_config: Dict[str, Any]
    jar_files: List[str]
    db_connections: Dict[str, Any]
    config_files: List[str]
    security: Dict[str, Any]


@dataclass
class WebServerAnalysis:
    """Web server analysis results."""
    server_type: str
    config_files: List[str]
    virtual_hosts: List[str]
    ssl_config: Dict[str, Any]
    modules: List[str]
    log_files: List[str]


@dataclass
class RedisAnalysis:
    """Redis analysis results."""
    server_type: str
    config_file: Optional[str]
    config_settings: Union[Dict[str, str], str]
    memory_usage: Union[Dict[str, int], str]
    network_config: Dict[str, str]
    persistence_config: Dict[str, Any]
    replication_config: Dict[str, Any]
    cluster_config: Dict[str, Any]


@dataclass
class SystemdAnalysis:
    """Systemd service analysis results."""
    service_info: Union[Dict[str, str], str]
    unit_file: Union[Dict[str, Any], str]
    service_status: Union[Dict[str, str], str]
    dependencies: Union[Dict[str, List[str]], str]
    resource_limits: Union[Dict[str, str], str]
    recent_logs: Union[List[str], str]
    cgroup_info: Union[Dict[str, Any], str]


@dataclass
class LaunchAnalysis:
    """Process launch method analysis."""
    launch_method: str
    parent_info: Union[Dict[str, Any], str]
    session_info: Union[Dict[str, Any], str]
    startup_clues: List[str]


@dataclass
class SystemdSuggestion:
    """Systemd migration suggestion."""
    service_file: str
    management_commands: str
    service_name: str


@dataclass
class AnalysisResult:
    """Complete analysis result containing all information."""
    process_info: ProcessInfo
    java_analysis: Optional[JavaAnalysis] = None
    webserver_analysis: Optional[WebServerAnalysis] = None
    redis_analysis: Optional[RedisAnalysis] = None
    systemd_analysis: Optional[SystemdAnalysis] = None
    launch_analysis: Optional[LaunchAnalysis] = None
    systemd_suggestion: Optional[Union[SystemdSuggestion, str]] = None
