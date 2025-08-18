# PY-PID-ANALYZER v2.0 - Code Reorganization

This document describes the new modular code structure implemented in version 2.0.

## Overview

The codebase has been completely reorganized from a single large file (`pid_analyzer.py`) into a modular package structure that follows Python best practices and design patterns.

## New Directory Structure

```
pid_analyzer/
├── __init__.py                    # Package initialization
├── main.py                       # CLI interface and main entry point
├── core/
│   ├── __init__.py
│   ├── analyzer.py              # Main ProcessAnalyzer class
│   └── process_detection.py     # Process type detection functions
├── analyzers/
│   ├── __init__.py
│   ├── base.py                  # Base analyzer interface
│   ├── java.py                  # Java-specific analysis
│   ├── webserver.py             # Web server analysis
│   ├── redis.py                 # Redis analysis
│   └── systemd.py               # Systemd analysis
├── output/
│   ├── __init__.py
│   ├── formatters.py            # Output formatting (Text, JSON)
│   └── handlers.py              # Output handlers (stdout, S3, file, etc.)
├── ui/
│   ├── __init__.py
│   └── interactive.py           # Interactive process selection
├── models/
│   ├── __init__.py
│   └── process_info.py          # Data models and dataclasses
└── config/
    ├── __init__.py
    └── settings.py              # Configuration management
```

## Key Improvements

### 1. **Modular Architecture**
- **Separation of Concerns**: Each module has a single responsibility
- **Loose Coupling**: Modules can be developed and tested independently
- **High Cohesion**: Related functionality is grouped together

### 2. **Plugin-Based Analyzer System**
- **Base Analyzer Interface**: All analyzers implement the same interface
- **Dynamic Loading**: Analyzers are loaded only when needed
- **Extensibility**: New analyzers can be added without modifying core code

### 3. **Structured Data Models**
- **Type Safety**: Using dataclasses for structured data
- **Validation**: Built-in validation for data integrity
- **Documentation**: Self-documenting code with type hints

### 4. **Flexible Output System**
- **Multiple Formatters**: Text, JSON, and extensible for HTML, CSV, etc.
- **Multiple Handlers**: stdout, file, S3, SMTP, CloudWatch
- **Pluggable Architecture**: Easy to add new output methods

### 5. **Configuration Management**
- **Centralized Settings**: All configuration in one place
- **User Overrides**: Support for user configuration files
- **Environment Awareness**: Platform-specific behavior

## Usage Examples

### Using the New Entry Point

```bash
# Use the new entry point script
python3 analyze_process.py 1234

# Or use the package directly
python3 -m pid_analyzer.main 1234

# Or use UV (if installed as package)
uv run pid-analyzer 1234
```

### Programmatic Usage

```python
from pid_analyzer.core.analyzer import ProcessAnalyzer
from pid_analyzer.output.formatters import JSONFormatter
from pid_analyzer.output.handlers import FileHandler

# Analyze a process
analyzer = ProcessAnalyzer(1234)
result = analyzer.analyze(enhanced=True)

# Output as JSON to file
formatter = JSONFormatter()
handler = FileHandler(formatter)
handler.output(result, file_path="analysis.json")
```

### Adding a New Analyzer

```python
from pid_analyzer.analyzers.base import BaseAnalyzer

class DatabaseAnalyzer(BaseAnalyzer):
    def detect(self, info):
        return 'mysql' in info['cmdline'].lower()
    
    def analyze(self, info):
        return {'database_type': 'MySQL', 'version': '8.0'}
    
    def get_analysis_name(self):
        return "database_analysis"
```

## Migration from v1.x

### For End Users
1. **Same CLI Interface**: All existing command-line options work the same
2. **Enhanced Features**: Better error handling and more output formats
3. **Backwards Compatibility**: Existing scripts should work unchanged

### For Developers
1. **Import Changes**: 
   ```python
   # Old way
   from pid_analyzer import ProcessAnalyzer
   
   # New way
   from pid_analyzer.core.analyzer import ProcessAnalyzer
   ```

2. **New Extension Points**: 
   - Custom analyzers via base class
   - Custom output formatters
   - Custom output handlers

## Benefits of the New Structure

### 1. **Maintainability**
- **Smaller Files**: Easier to understand and modify
- **Clear Dependencies**: Import relationships are explicit
- **Modular Testing**: Each component can be tested independently

### 2. **Extensibility**
- **Plugin Architecture**: Add new analyzers without core changes
- **Output Flexibility**: Support for new output formats and destinations
- **Configuration System**: Easy to add new settings

### 3. **Code Quality**
- **Type Hints**: Better IDE support and error detection
- **Design Patterns**: Following established Python patterns
- **Documentation**: Self-documenting code structure

### 4. **Performance**
- **Lazy Loading**: Analyzers loaded only when needed
- **Memory Efficiency**: Better resource management
- **Import Optimization**: Faster startup times

## Testing the New Structure

Run the included test script to verify the reorganization:

```bash
python3 test_reorganized_code.py
```

This will test:
- Module imports
- Process detection functions
- Output formatters
- Configuration system

## Platform Support

The reorganized code maintains the same Linux-only focus:
- **Supported**: Linux distributions
- **Not Supported**: macOS, Windows
- **Detection**: Automatic platform validation with clear error messages

## Future Enhancements

The new structure enables:
1. **Web Interface**: Easy to add a Flask/FastAPI web UI
2. **REST API**: Simple to expose functionality via API
3. **Monitoring Integration**: Plugin-based monitoring system integration
4. **CI/CD Pipeline**: Structured testing and deployment
5. **Documentation**: Auto-generated API documentation

## Backward Compatibility

- Original `pid_analyzer.py` remains as legacy code
- New `analyze_process.py` provides the same interface
- All CLI options and output formats preserved
- Gradual migration path for existing integrations
