# HOWTO: Setup and Usage Guide

## Quick Start with UV

### Prerequisites
- Linux system (Ubuntu, CentOS, Amazon Linux, etc.)
- Python 3.12+ 
- UV package manager ([install UV](https://docs.astral.sh/uv/getting-started/installation/))

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd py-pid-analyzer

# UV automatically creates virtual environment and installs dependencies
uv sync
```

### Basic Usage

```bash
# Interactive mode - browse and select processes
uv run pid_analyzer.py

# Analyze specific PID
uv run pid_analyzer.py 1234

# Non-interactive analysis
uv run pid_analyzer.py 1234 --non-interactive
```

### Output Options

```bash
# Save to file
uv run pid_analyzer.py 1234 --output file --file-path analysis.txt

# Upload to S3 (requires AWS credentials)
uv run pid_analyzer.py 1234 --output s3 --s3-uri s3://bucket/analysis.txt

# Send to CloudWatch Logs
uv run pid_analyzer.py 1234 --output cloudwatch --log-group /aws/analysis

# Email results
uv run pid_analyzer.py 1234 --output smtp --smtp-server smtp.gmail.com --smtp-port 587 --smtp-user user@gmail.com --smtp-password <password> --smtp-to recipient@example.com
```

## Enhanced Analysis Examples

### Java Applications
```bash
# Analyze Tomcat process (enhanced analysis will be prompted)
uv run pid_analyzer.py $(pgrep java)

# Force enhanced analysis without prompts
uv run pid_analyzer.py $(pgrep java) --non-interactive
```

### Web Servers
```bash
# Analyze Nginx
uv run pid_analyzer.py $(pgrep nginx)

# Analyze Apache
uv run pid_analyzer.py $(pgrep apache2)
```

## Development Setup

### Adding Dependencies
```bash
# Add new dependency
uv add requests

# Add development dependency
uv add --dev pytest

# Add optional dependency group
uv add --optional visualization matplotlib plotly
```

### Running Tests
```bash
# Install test dependencies
uv add --dev pytest pytest-cov

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=pid_analyzer
```

## Troubleshooting

### Permission Issues
```bash
# Run with sudo for system processes
sudo $(uv run which python) pid_analyzer.py 1234

# Or use UV with sudo
sudo uv run pid_analyzer.py 1234
```

### AWS Configuration
```bash
# Configure AWS credentials (for S3/CloudWatch output)
aws configure

# Or use environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### Common Process Discovery
```bash
# Find Java processes
uv run pid_analyzer.py $(pgrep -f java)

# Find web server processes
uv run pid_analyzer.py $(pgrep -f "nginx|apache|httpd")

# Find database processes
uv run pid_analyzer.py $(pgrep -f "mysql|postgres|mongo")
```

## Project Structure
```
py-pid-analyzer/
├── pid_analyzer.py          # Main application
├── pyproject.toml          # UV project configuration
├── uv.lock                 # Dependency lock file
├── requirements.txt        # Legacy pip requirements
├── README.md              # Project overview
├── HOWTO.md               # This guide
├── TODO.md                # Implementation roadmap
├── DEVELOPMENT_GUIDE.md   # Development guidelines
└── FUTURE_ROADMAP.md      # Long-term vision
```

## Next Steps
- See [README.md](README.md) for feature overview
- See [TODO.md](TODO.md) for planned enhancements
- See [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) for contributing