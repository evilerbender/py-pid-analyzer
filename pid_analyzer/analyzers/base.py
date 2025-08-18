"""
Base analyzer interface and common functionality.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import psutil

from ..models.process_info import ProcessInfo


class BaseAnalyzer(ABC):
    """Base class for all specialized analyzers."""
    
    def __init__(self, process: psutil.Process):
        self.process = process
    
    @abstractmethod
    def detect(self, info: Dict[str, Any]) -> bool:
        """Detect if this analyzer applies to the process."""
        pass
    
    @abstractmethod
    def analyze(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform specialized analysis."""
        pass
    
    @abstractmethod
    def get_analysis_name(self) -> str:
        """Get the name of this analysis type."""
        pass


class AnalyzerRegistry:
    """Registry for managing available analyzers."""
    
    def __init__(self):
        self._analyzers = {}
    
    def register(self, name: str, analyzer_class: type):
        """Register an analyzer class."""
        self._analyzers[name] = analyzer_class
    
    def get_applicable_analyzers(self, process: psutil.Process, info: Dict[str, Any]):
        """Get analyzers that apply to the given process."""
        applicable = []
        for name, analyzer_class in self._analyzers.items():
            analyzer = analyzer_class(process)
            if analyzer.detect(info):
                applicable.append((name, analyzer))
        return applicable
    
    def get_analyzer(self, name: str) -> Optional[type]:
        """Get an analyzer class by name."""
        return self._analyzers.get(name)
    
    def list_analyzers(self):
        """List all registered analyzers."""
        return list(self._analyzers.keys())


# Global registry instance
analyzer_registry = AnalyzerRegistry()
