# Code Reorganization - Version 2.0.0

This document describes the major code reorganization implemented in version 2.0.0 of PY-PID-ANALYZER.

## New Structure

The code has been reorganized from a single 1800+ line file into a modular package structure:

```
pid_analyzer/                    # Main package
├── __init__.py                 # Package initialization
├── main.py                     # CLI interface and main function
├── core/                       # Core functionality
│   ├── __init__.py
│   ├── analyzer.py            # Main ProcessAnalyzer class
│   └── process_detection.py   # Detection functions
├── analyzers/                  # Specialized analyzers
│   ├── __init__.py
│   ├── base.py               # Base analyzer interface
│   ├── java.py               # Java-specific analysis
│   ├── webserver.py          # Web server analysis
│   ├── redis.py              # Redis analysis
│   └── systemd.py            # Systemd analysis
├── models/                     # Data models
│   ├── __init__.py
│   └── process_info.py       # ProcessInfo and analysis result models
├── output/                     # Output formatting and handling
│   ├── __init__.py
│   ├── formatters.py         # Text and JSON formatters
│   └── handlers.py           # S3, SMTP, file handlers
├── ui/                        # User interface components
│   ├── __init__.py
│   └── interactive.py        # Interactive process selection
└── config/                    # Configuration management
    ├── __init__.py
    └── settings.py           # Configuration system
```

## Key Improvements

### 1. Modular Architecture
- **Separation of Concerns**: Each module has a specific responsibility
- **Plugin Architecture**: Analyzers can be easily added through the registry system
- **Extensibility**: New analyzers follow a standard interface

### 2. Better Data Models
- **Type Safety**: Uses dataclasses for structured data
- **Consistency**: Standardized data structures across all analyzers
- **Documentation**: Clear data model definitions

### 3. Flexible Output System
- **Multiple Formatters**: Text, JSON (easily extendable to HTML, CSV, etc.)
- **Multiple Handlers**: stdout, file, S3, SMTP, CloudWatch
- **Configurable**: Output behavior can be customized

### 4. Improved Error Handling
- **Graceful Degradation**: Missing optional dependencies don't break core functionality
- **Better Error Messages**: More informative error reporting
- **Logging Support**: Framework for structured logging

### 5. Configuration Management
- **Default Settings**: Sensible defaults for all analyzers
- **User Overrides**: YAML-based configuration files
- **Environment-Specific**: Different configs for different environments

## Migration Guide

### For Users

The command-line interface remains mostly the same:

```bash
# Old way (still works)
python3 pid_analyzer.py 1234

# New way (recommended)
python3 analyze.py 1234

# Or using the installed script
pid-analyzer 1234
```

### For Developers

#### Adding New Analyzers

1. Create a new analyzer class inheriting from `BaseAnalyzer`:

```python
# analyzers/myanalyzer.py
from .base import BaseAnalyzer

class MyAnalyzer(BaseAnalyzer):
    def detect(self, info):
        # Detection logic
        return True
    
    def analyze(self, info):
        # Analysis logic
        return {}
    
    def get_analysis_name(self):
        return "my_analysis"
```

2. Register the analyzer:

```python
# In __init__.py or main registration area
from .analyzers.myanalyzer import MyAnalyzer
analyzer_registry.register('my', MyAnalyzer)
```

#### Adding New Output Formats

1. Create a new formatter:

```python
# output/formatters.py
class HTMLFormatter(OutputFormatter):
    def format(self, result):
        # HTML formatting logic
        return html_content
```

2. Create a new handler if needed:

```python
# output/handlers.py
class WebhookHandler(OutputHandler):
    def output(self, analysis_result, webhook_url, **kwargs):
        # Webhook posting logic
        pass
```

## Backward Compatibility

- The original `pid_analyzer.py` is preserved for reference
- All existing command-line options work with the new structure
- Analysis output format remains the same by default
- All existing features are preserved

## Future Enhancements

The new structure enables:

1. **Easy Testing**: Each module can be tested independently
2. **Plugin System**: Third-party analyzers can be easily integrated
3. **API Mode**: REST API wrapper can be easily added
4. **Configuration**: YAML-based configuration for customization
5. **Packaging**: Better distribution and installation options

## Dependencies

### Required
- `psutil>=5.9.0`: Core process analysis functionality

### Optional
- `boto3>=1.26.0`: AWS services (S3, CloudWatch) - install with `pip install py-pid-analyzer[aws]`
- `pyyaml>=6.0`: YAML configuration files - install with `pip install py-pid-analyzer[yaml]`

Install all optional dependencies with:
```bash
pip install py-pid-analyzer[all]
```

## Performance

The modular structure has these performance characteristics:

- **Startup Time**: Slightly increased due to module loading
- **Memory Usage**: Reduced due to lazy loading of analyzers
- **Analysis Speed**: Unchanged or slightly improved due to better code organization
- **Extensibility**: Much improved due to plugin architecture

## Testing

Run the reorganized code:

```bash
# Test basic import
python3 -c "import pid_analyzer; print('Success')"

# Test CLI
python3 analyze.py --help

# Test with a process
python3 analyze.py 1
```
