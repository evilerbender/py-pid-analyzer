"""Specialized process analyzers."""

from .base import analyzer_registry

# Import and register analyzers
def register_all_analyzers():
    """Register all available analyzers."""
    try:
        from .java import JavaAnalyzer
        analyzer_registry.register('java', JavaAnalyzer)
    except ImportError:
        pass
    
    try:
        from .webserver import WebServerAnalyzer
        analyzer_registry.register('webserver', WebServerAnalyzer)
    except ImportError:
        pass
    
    try:
        from .redis import RedisAnalyzer
        analyzer_registry.register('redis', RedisAnalyzer)
    except ImportError:
        pass
    
    try:
        from .systemd import SystemdAnalyzer
        analyzer_registry.register('systemd', SystemdAnalyzer)
    except ImportError:
        pass

# Register analyzers on import
register_all_analyzers()
