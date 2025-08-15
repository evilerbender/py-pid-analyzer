# PY-PID-ANALYZER Development Guide

## Project Overview
A Python utility for analyzing process IDs with specialized enhanced analysis for different application types (Java/Tomcat, web servers, databases, etc.).

**Platform Support**: Linux-only. This project exclusively targets Linux-based systems and will not support Windows or other non-Linux operating systems.

## Current Architecture

### Core Components
- **`pid_analyzer.py`** - Main analyzer with ProcessAnalyzer class
- **`pyproject.toml`** - UV project configuration and dependencies
- **`requirements.txt`** - Legacy pip dependencies (psutil>=5.9.0, boto3>=1.26.0)
- **`README.md`** - Project description and requirements
- **`HOWTO.md`** - Setup and usage guide with UV instructions
- **`TODO.md`** - Feature implementation roadmap
- **`DEVELOPMENT_GUIDE.md`** - Core project direction and style guidelines
- **`FUTURE_ROADMAP.md`** - Ideas for future features and enhancements selection

### Key Features Implemented
1. **Basic Process Analysis**: PID, name, status, command line, executable, working directory
2. **Environment Analysis**: Environment variables, memory maps, open files, network connections
3. **Interactive Process Selection**: Paginated menu with sorting (PID, name, runtime, user) and filtering (user processes, all processes, specific user)
4. **Multiple Output Methods**: stdout, S3, filesystem, SMTP, CloudWatch Logs
5. **Privilege Management**: Root permission checking with escalation prompts
6. **Java/Tomcat Enhanced Analysis**: JVM config, application type detection, JAR files, database connections, configuration files, security settings

### ProcessAnalyzer Class Structure
```python
class ProcessAnalyzer:
    def __init__(self, pid)
    def analyze(self, enhanced=False)  # Main analysis method
    def _get_memory_maps()
    def _get_open_files()
    def _get_connections()
    
    # Java-specific methods (template for other analyzers)
    def _analyze_java_process(self, info)
    def _parse_jvm_args(self, info)
    def _identify_java_app_type(self, info)
    def _get_jar_files(self, info)
    def _analyze_db_connections(self, info)
    def _get_config_files(self, info)
    def _analyze_security_settings(self, info)
```

## Adding New Specialized Analyzers

### Step 1: Detection Function
Create a detection function following the pattern:
```python
def is_[TYPE]_process(info):
    """Check if process is a [TYPE] application"""
    if info['cmdline'] == 'Access denied':
        return False
    
    cmdline = info['cmdline'].lower()
    # Add detection logic based on command line, process name, environment variables
    return [detection_condition]
```

### Step 2: Analysis Methods
Add specialized analysis methods to ProcessAnalyzer class:
```python
def _analyze_[TYPE]_process(self, info):
    """Enhanced analysis for [TYPE] processes"""
    analysis = {}
    analysis['config'] = self._parse_[TYPE]_config(info)
    analysis['app_type'] = self._identify_[TYPE]_app_type(info)
    # Add other analysis components
    return analysis
```

### Step 3: Update Main Analysis
Modify the `analyze()` method to include new analyzer:
```python
if enhanced:
    if is_java_process(info):
        info['java_analysis'] = self._analyze_java_process(info)
    elif is_[TYPE]_process(info):
        info['[TYPE]_analysis'] = self._analyze_[TYPE]_process(info)
```

### Step 4: Update Detection in Main
Add detection to main function:
```python
enhanced = False
if is_java_process(info) and not args.non_interactive:
    # existing Java detection
elif is_[TYPE]_process(info) and not args.non_interactive:
    response = input(f"\nDetected [TYPE] application. Include enhanced analysis? (y/N): ")
    if response.lower() in ['y', 'yes']:
        enhanced = True
```

### Step 5: Update Output Formatting
Add formatting in `format_analysis()` function:
```python
# After Java analysis section
if '[TYPE]_analysis' in info:
    [TYPE] = info['[TYPE]_analysis']
    output.write(f"\n{'='*50}\n")
    output.write("[TYPE] APPLICATION ANALYSIS\n")
    output.write(f"{'='*50}\n")
    # Add specific formatting
```

## Command Line Interface

### Arguments
- `pid` (optional) - Process ID to analyze
- `--non-interactive` - Run without prompts
- `--output` - Output method (stdout, s3, file, smtp, cloudwatch)
- Output-specific arguments for each method

### Interactive Features
- Process selection menu with pagination
- Sorting options (PID, name, runtime, user)
- Filtering options (user processes, all processes, specific user)
- Enhanced analysis prompts for detected application types

## Development Workflow

### Adding New Process Type
1. Choose from TODO.md list
2. Research process characteristics (command patterns, config files, ports, etc.)
3. Implement detection function
4. Add specialized analysis methods
5. Update main analysis flow
6. Add output formatting
7. Test with real process instances
8. Update TODO.md to mark as completed

### Testing Approach
- Test with actual running processes of each type on Linux systems
- Verify detection accuracy across different Linux distributions
- Ensure enhanced analysis provides valuable insights
- Test with different privilege levels (root vs non-root)
- Validate output formatting
- Test on various Linux environments (Ubuntu, CentOS, Amazon Linux, etc.)

## File Structure
```
py-pid-analyzer/
├── pid_analyzer.py          # Main application
├── pyproject.toml          # UV project configuration
├── uv.lock                 # Dependency lock file
├── requirements.txt        # Legacy pip dependencies
├── README.md               # Project description
├── HOWTO.md                # Setup and usage guide
├── TODO.md                 # Implementation roadmap
└── DEVELOPMENT_GUIDE.md    # This file
```

## Dependencies
- **psutil**: Linux process information (cross-platform library used in Linux-only mode)
- **boto3**: AWS services (S3, CloudWatch Logs) - optional for cloud output
- **Standard library**: os, sys, argparse, subprocess, json, smtplib, pathlib

**Note**: While psutil is cross-platform, this project uses it exclusively for Linux process analysis.

### Development Setup
```bash
# Using UV (recommended)
uv sync

# Add development dependencies
uv add --dev pytest pytest-cov

# Run tests
uv run pytest
```

## Usage Examples
```bash
# Interactive mode with process selection (UV recommended)
uv run pid_analyzer.py

# Direct PID analysis
uv run pid_analyzer.py 1234

# Non-interactive mode
uv run pid_analyzer.py 1234 --non-interactive

# Output to file
uv run pid_analyzer.py 1234 --output file --file-path analysis.txt

# Output to S3
uv run pid_analyzer.py 1234 --output s3 --s3-uri s3://bucket/analysis.txt
```

## Optional Libraries Implementation Guidelines

### Core Principles
- All optional libraries must be truly optional with graceful degradation
- Core functionality must work without any optional dependencies
- Optional features should be clearly documented as requiring additional libraries
- Use try/except imports with informative error messages for missing libraries
- Provide installation instructions for optional dependencies in separate requirements files
- Consider creating requirements-extras.txt for optional dependencies
- Implement feature detection to enable/disable functionality based on available libraries

### Implementation Pattern
```python
try:
    import optional_library
    HAS_OPTIONAL_LIBRARY = True
except ImportError:
    HAS_OPTIONAL_LIBRARY = False

def enhanced_feature():
    if not HAS_OPTIONAL_LIBRARY:
        print("Enhanced feature requires 'optional_library'. Install with: pip install optional_library")
        return basic_fallback()
    return optional_library.enhanced_function()
```

## Next Steps
1. Choose next process type from TODO.md
2. Follow the implementation pattern established by Java analyzer
3. Test thoroughly with real processes
4. Update documentation and TODO.md