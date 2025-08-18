"""
Output formatters for analysis results.
"""

import os
from abc import ABC, abstractmethod
from io import StringIO
from typing import Dict, Any, Union

from ..models.process_info import AnalysisResult


class OutputFormatter(ABC):
    """Base class for output formatters."""
    
    @abstractmethod
    def format(self, result: AnalysisResult) -> str:
        """Format the analysis result."""
        pass


class TextFormatter(OutputFormatter):
    """Plain text formatter."""
    
    def format(self, result: AnalysisResult) -> str:
        """Format analysis results as plain text."""
        output = StringIO()
        info = result.process_info
        
        output.write(f"Process Analysis for PID {info.pid}\n")
        output.write("=" * 50 + "\n")
        
        # Basic process info
        self._format_basic_info(output, info)
        
        # Environment variables
        self._format_environment(output, info)
        
        # Memory maps
        self._format_memory_maps(output, info)
        
        # Open files
        self._format_open_files(output, info)
        
        # Network connections
        self._format_connections(output, info)
        
        # Shared libraries
        self._format_shared_libraries(output, info)
        
        # Specialized analyses
        if result.java_analysis:
            self._format_java_analysis(output, result.java_analysis)
        
        if result.webserver_analysis:
            self._format_webserver_analysis(output, result.webserver_analysis)
        
        if result.redis_analysis:
            self._format_redis_analysis(output, result.redis_analysis)
        
        if result.systemd_analysis:
            self._format_systemd_analysis(output, result.systemd_analysis)
        
        if result.launch_analysis:
            self._format_launch_analysis(output, result.launch_analysis)
        
        if result.systemd_suggestion:
            self._format_systemd_suggestion(output, result.systemd_suggestion)
        
        return output.getvalue()
    
    def _format_basic_info(self, output: StringIO, info):
        """Format basic process information."""
        output.write(f"Name: {info.name}\n")
        output.write(f"Status: {info.status}\n")
        output.write(f"Command: {info.cmdline}\n")
        output.write(f"Executable: {info.exe}\n")
        output.write(f"Working Directory: {info.cwd}\n")
    
    def _format_environment(self, output: StringIO, info):
        """Format environment variables."""
        output.write("\nEnvironment Variables:\n")
        if isinstance(info.environ, dict):
            for key, value in list(info.environ.items())[:10]:
                output.write(f"  {key}={value}\n")
            if len(info.environ) > 10:
                output.write(f"  ... and {len(info.environ) - 10} more\n")
        else:
            output.write(f"  {info.environ}\n")
    
    def _format_memory_maps(self, output: StringIO, info):
        """Format memory maps."""
        output.write(f"\nMemory Maps ({len(info.memory_maps) if isinstance(info.memory_maps, list) else 0}):\n")
        if isinstance(info.memory_maps, list):
            for mmap in info.memory_maps[:5]:
                output.write(f"  {mmap['path']} (RSS: {mmap['rss']} bytes)\n")
            if len(info.memory_maps) > 5:
                output.write(f"  ... and {len(info.memory_maps) - 5} more\n")
        else:
            output.write(f"  {info.memory_maps}\n")
    
    def _format_open_files(self, output: StringIO, info):
        """Format open files."""
        output.write(f"\nOpen Files ({len(info.open_files) if isinstance(info.open_files, list) else 0}):\n")
        if isinstance(info.open_files, list):
            for f in info.open_files[:5]:
                output.write(f"  FD {f['fd']}: {f['path']} ({f['mode']})\n")
            if len(info.open_files) > 5:
                output.write(f"  ... and {len(info.open_files) - 5} more\n")
        else:
            output.write(f"  {info.open_files}\n")
    
    def _format_connections(self, output: StringIO, info):
        """Format network connections."""
        output.write(f"\nNetwork Connections ({len(info.connections) if isinstance(info.connections, list) else 0}):\n")
        if isinstance(info.connections, list):
            for conn in info.connections:
                output.write(f"  {conn['family']}/{conn['type']}: {conn['laddr']} -> {conn['raddr']} ({conn['status']})\n")
        else:
            output.write(f"  {info.connections}\n")
    
    def _format_shared_libraries(self, output: StringIO, info):
        """Format shared libraries analysis."""
        if isinstance(info.shared_libraries, dict):
            libs = info.shared_libraries
            output.write(f"\n{'='*50}\n")
            output.write("SHARED LIBRARIES ANALYSIS\n")
            output.write(f"{'='*50}\n")
            output.write(f"Total Memory Mappings: {libs['total_count']}\n")
            output.write(f"Unique Library Directories: {len(libs['unique_directories'])}\n")
            
            # System Libraries
            if libs['system_libraries']:
                output.write(f"\nSystem Libraries ({len(libs['system_libraries'])}):\n")
                by_category = {}
                for lib in libs['system_libraries']:
                    subcat = lib.get('subcategory', 'other')
                    if subcat not in by_category:
                        by_category[subcat] = []
                    by_category[subcat].append(lib)
                
                for category, category_libs in by_category.items():
                    if category_libs:
                        output.write(f"\n  {category.replace('_', ' ').title()} Libraries ({len(category_libs)}):\n")
                        for lib in category_libs:
                            size_mb = lib['rss'] / (1024 * 1024)
                            output.write(f"    {os.path.basename(lib['path'])} ({size_mb:.1f} MB)\n")
            
            # Language-Specific Libraries
            if libs['language_specific']:
                output.write(f"\nLanguage-Specific Libraries ({len(libs['language_specific'])}):\n")
                by_language = {}
                for lib in libs['language_specific']:
                    lang = lib.get('language', 'unknown')
                    if lang not in by_language:
                        by_language[lang] = []
                    by_language[lang].append(lib)
                
                for language, lang_libs in by_language.items():
                    if lang_libs:
                        output.write(f"\n  {language.title()} Libraries ({len(lang_libs)}):\n")
                        for lib in lang_libs[:3]:
                            size_mb = lib['rss'] / (1024 * 1024)
                            output.write(f"    {os.path.basename(lib['path'])} ({size_mb:.1f} MB)\n")
                        if len(lang_libs) > 3:
                            output.write(f"    ... and {len(lang_libs) - 3} more\n")
        
        elif isinstance(info.shared_libraries, str):
            output.write(f"\nShared Libraries: {info.shared_libraries}\n")
    
    def _format_java_analysis(self, output: StringIO, java):
        """Format Java analysis."""
        output.write(f"\n{'='*50}\n")
        output.write("JAVA APPLICATION ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        output.write(f"Application Type: {java.app_type}\n")
        
        if isinstance(java.jvm_config, dict):
            output.write("\nJVM Configuration:\n")
            if java.jvm_config['heap_size']:
                for key, value in java.jvm_config['heap_size'].items():
                    output.write(f"  Heap {key}: {value}\n")
            if java.jvm_config['gc_settings']:
                output.write(f"  GC Settings: {', '.join(java.jvm_config['gc_settings'][:3])}\n")
        
        if java.jar_files:
            output.write(f"\nLoaded JAR Files ({len(java.jar_files)}):\n")
            for jar in java.jar_files[:5]:
                output.write(f"  {jar}\n")
            if len(java.jar_files) > 5:
                output.write(f"  ... and {len(java.jar_files) - 5} more\n")
    
    def _format_webserver_analysis(self, output: StringIO, web):
        """Format web server analysis."""
        output.write(f"\n{'='*50}\n")
        output.write("WEB SERVER ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        output.write(f"Server Type: {web.server_type}\n")
        
        if web.config_files:
            output.write(f"\nConfiguration Files ({len(web.config_files)}):\n")
            for config in web.config_files[:5]:
                output.write(f"  {config}\n")
            if len(web.config_files) > 5:
                output.write(f"  ... and {len(web.config_files) - 5} more\n")
    
    def _format_redis_analysis(self, output: StringIO, redis):
        """Format Redis analysis."""
        output.write(f"\n{'='*50}\n")
        output.write("REDIS ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        output.write(f"Server Type: {redis.server_type}\n")
        
        if redis.config_file:
            output.write(f"\nConfiguration File: {redis.config_file}\n")
        else:
            output.write(f"\nConfiguration: Using default settings (no config file)\n")
    
    def _format_systemd_analysis(self, output: StringIO, systemd):
        """Format systemd analysis."""
        output.write(f"\n{'='*50}\n")
        output.write("SYSTEMD SERVICE ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        if isinstance(systemd.service_info, dict):
            output.write("Service Information:\n")
            key_props = ['Id', 'Description', 'Type', 'ExecStart', 'User', 'Group', 'MainPID']
            for prop in key_props:
                if prop in systemd.service_info:
                    output.write(f"  {prop}: {systemd.service_info[prop]}\n")
        elif isinstance(systemd.service_info, str):
            output.write(f"Service Information: {systemd.service_info}\n")
    
    def _format_launch_analysis(self, output: StringIO, launch):
        """Format launch analysis."""
        output.write(f"\n{'='*50}\n")
        output.write("PROCESS LAUNCH ANALYSIS\n")
        output.write(f"{'='*50}\n")
        
        if isinstance(launch, dict):
            output.write(f"Launch Method: {launch.get('launch_method', 'unknown')}\n")
            
            if launch.get('startup_clues'):
                output.write(f"\nStartup Clues:\n")
                for clue in launch.startup_clues:
                    output.write(f"  • {clue}\n")
        else:
            output.write(f"Launch Analysis: {launch}\n")
    
    def _format_systemd_suggestion(self, output: StringIO, suggestion):
        """Format systemd suggestion."""
        output.write(f"\n{'='*50}\n")
        output.write("SYSTEMD MIGRATION SUGGESTION\n")
        output.write(f"{'='*50}\n")
        
        if hasattr(suggestion, 'service_file'):
            output.write("Suggested systemd service unit file:\n\n")
            output.write(suggestion.service_file)
            output.write("\n")
            
            if hasattr(suggestion, 'management_commands'):
                output.write(suggestion.management_commands)
                output.write("\n")
        elif isinstance(suggestion, str):
            output.write(f"Systemd Suggestion: {suggestion}\n")


class JSONFormatter(OutputFormatter):
    """JSON formatter."""
    
    def format(self, result: AnalysisResult) -> str:
        """Format analysis results as JSON."""
        import json
        
        # Convert dataclass to dictionary for JSON serialization
        data = {
            'process_info': self._convert_to_dict(result.process_info),
            'java_analysis': self._convert_to_dict(result.java_analysis) if result.java_analysis else None,
            'webserver_analysis': self._convert_to_dict(result.webserver_analysis) if result.webserver_analysis else None,
            'redis_analysis': self._convert_to_dict(result.redis_analysis) if result.redis_analysis else None,
            'systemd_analysis': self._convert_to_dict(result.systemd_analysis) if result.systemd_analysis else None,
            'launch_analysis': self._convert_to_dict(result.launch_analysis) if result.launch_analysis else None,
            'systemd_suggestion': self._convert_to_dict(result.systemd_suggestion) if result.systemd_suggestion else None,
        }
        
        return json.dumps(data, indent=2, default=str)
    
    def _convert_to_dict(self, obj):
        """Convert dataclass to dictionary."""
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return obj
