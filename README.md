# PY-PID-ANALYZER

A Python utility for analyzing Linux process IDs with specialized enhanced analysis for different application types.

## Overview

PY-PID-ANALYZER provides comprehensive process analysis capabilities, including basic process information, environment analysis, and specialized enhanced analysis for detected application types like Java/Tomcat and web servers.

**Platform Support**: Linux-only. This project exclusively targets Linux-based systems.

## Features

### ✅ Current Capabilities
- **Basic Process Analysis**: PID, name, status, command line, executable, working directory
- **Environment Analysis**: Environment variables, memory maps, open files, network connections
- **Interactive Process Selection**: Paginated menu with sorting and filtering options
- **Multiple Output Methods**: stdout, S3, filesystem, SMTP, CloudWatch Logs
- **Privilege Management**: Root permission checking with escalation prompts
- **Enhanced Analysis for**:
  - Java Applications (Tomcat, Spring, Jetty, WildFly/JBoss)
  - Web Servers & Reverse Proxies (Apache HTTP Server, Nginx, HAProxy)

### 🔄 Planned Enhancements
- Database servers (MySQL, PostgreSQL, MongoDB, Redis)
- Container runtimes (Docker, Podman, containerd)
- Python applications (Django, Flask, FastAPI, Gunicorn, uWSGI)
- Message brokers (RabbitMQ, Apache Kafka, ActiveMQ)
- Monitoring tools (Prometheus, Grafana, ELK Stack)
- AI agent analysis enhancements with structured metadata
- Optional libraries for specialized functionality

## Installation

### Using UV (Recommended)
```bash
# Clone repository
git clone <repository-url>
cd py-pid-analyzer

# UV automatically creates virtual environment and installs dependencies
uv sync
```

### Using pip
```bash
# Clone repository
git clone <repository-url>
cd py-pid-analyzer

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Interactive Mode
```bash
# Using UV (recommended)
uv run pid_analyzer.py

# Using Python directly
python3 pid_analyzer.py
```

### Direct PID Analysis
```bash
# Using UV
uv run pid_analyzer.py 1234

# Non-interactive mode
uv run pid_analyzer.py 1234 --non-interactive
```

### Output Options
```bash
# Output to file
uv run pid_analyzer.py 1234 --output file --file-path analysis.txt

# Output to S3
uv run pid_analyzer.py 1234 --output s3 --s3-uri s3://bucket/analysis.txt

# Output to CloudWatch Logs
uv run pid_analyzer.py 1234 --output cloudwatch --log-group /aws/analysis
```

## Dependencies

### Required
- **psutil** (>=5.9.0): Linux process information
- **boto3** (>=1.26.0): AWS services integration

### Optional Libraries
Optional libraries provide enhanced functionality while maintaining core compatibility:
- **cryptography**: Encrypted output and secure data handling
- **matplotlib/plotly**: Process visualization and performance graphs
- **requests**: Webhook notifications and API integrations
- **rich**: Enhanced terminal UI and colored output
- **pyyaml**: YAML configuration file parsing

## Project Structure

```
py-pid-analyzer/
├── pid_analyzer.py          # Main application
├── pyproject.toml          # UV project configuration
├── uv.lock                 # Dependency lock file
├── requirements.txt        # Legacy pip requirements
├── README.md               # This file
├── HOWTO.md                # Setup and usage guide
├── TODO.md                 # Implementation roadmap
├── DEVELOPMENT_GUIDE.md    # Development guidelines
├── FUTURE_ROADMAP.md       # Long-term vision
└── .amazonq/rules/         # Development rules
```

## Development

See [HOWTO.md](HOWTO.md) for setup and usage instructions.

See [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) for:
- Adding new specialized analyzers
- Implementation patterns
- Testing approaches
- Optional library integration guidelines

See [TODO.md](TODO.md) for current implementation roadmap.

See [FUTURE_ROADMAP.md](FUTURE_ROADMAP.md) for long-term vision and advanced features.

## Core Principles

- **Read-only by default**: All operations default to read-only with warnings for non-read operations
- **Minimal dependencies**: Favor Python standard libraries over external dependencies
- **Linux-focused**: Exclusively targets Linux-based systems
- **Extensible design**: Built for future enhancements and specialized analyzers
- **Security-conscious**: No sensitive data committed to repository

## Contributing

Contributions welcome! Please:
1. Follow the patterns established in existing analyzers
2. Update applicable documentation (TODO.md, DEVELOPMENT_GUIDE.md)
3. Test with real processes on Linux systems
4. Maintain read-only default behavior with appropriate warnings

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
