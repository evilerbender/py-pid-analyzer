#!/usr/bin/env python3
"""
Entry point for the reorganized PY-PID-ANALYZER.
"""

import sys
import os

# Add the package directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pid_analyzer.main import main

if __name__ == '__main__':
    sys.exit(main())
