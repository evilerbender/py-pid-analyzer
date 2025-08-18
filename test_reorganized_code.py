#!/usr/bin/env python3
"""
Simple test to verify the reorganized code structure works.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing module imports...")
    
    try:
        # Test core imports
        from pid_analyzer.core.process_detection import (
            is_java_process, is_webserver_process, is_redis_process, is_systemd_managed_process
        )
        print("✓ Core process detection functions imported")
        
        # Test models
        from pid_analyzer.models.process_info import ProcessInfo, AnalysisResult
        print("✓ Data models imported")
        
        # Test analyzers
        from pid_analyzer.analyzers.base import BaseAnalyzer
        print("✓ Base analyzer imported")
        
        from pid_analyzer.analyzers.java import JavaAnalyzer
        print("✓ Java analyzer imported")
        
        from pid_analyzer.analyzers.webserver import WebServerAnalyzer
        print("✓ Web server analyzer imported")
        
        from pid_analyzer.analyzers.redis import RedisAnalyzer
        print("✓ Redis analyzer imported")
        
        from pid_analyzer.analyzers.systemd import SystemdAnalyzer
        print("✓ Systemd analyzer imported")
        
        # Test output components
        from pid_analyzer.output.formatters import TextFormatter, JSONFormatter
        print("✓ Output formatters imported")
        
        from pid_analyzer.output.handlers import StdoutHandler, FileHandler
        print("✓ Output handlers imported")
        
        # Test UI
        from pid_analyzer.ui.interactive import ProcessSelector
        print("✓ Interactive UI imported")
        
        # Test main components
        from pid_analyzer.main import main
        print("✓ Main CLI imported")
        
        print("\n✅ All imports successful!")
        return True
        
    except ImportError as e:
        print(f"\n❌ Import error: {e}")
        return False

def test_process_detection():
    """Test process detection functions."""
    print("\nTesting process detection functions...")
    
    try:
        from pid_analyzer.core.process_detection import (
            is_java_process, is_webserver_process, is_redis_process
        )
        
        # Test Java detection
        java_info = {
            'cmdline': 'java -jar myapp.jar catalina.base=/opt/tomcat',
            'name': 'java'
        }
        assert is_java_process(java_info) == True
        print("✓ Java process detection works")
        
        # Test web server detection
        nginx_info = {
            'cmdline': '/usr/sbin/nginx -g daemon off;',
            'name': 'nginx'
        }
        assert is_webserver_process(nginx_info) == True
        print("✓ Web server detection works")
        
        # Test Redis detection
        redis_info = {
            'cmdline': '/usr/bin/redis-server /etc/redis.conf',
            'name': 'redis-server'
        }
        assert is_redis_process(redis_info) == True
        print("✓ Redis detection works")
        
        print("✅ Process detection tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Process detection test failed: {e}")
        return False

def test_formatters():
    """Test output formatters."""
    print("\nTesting output formatters...")
    
    try:
        from pid_analyzer.output.formatters import TextFormatter, JSONFormatter
        from pid_analyzer.models.process_info import ProcessInfo, AnalysisResult
        
        # Create a simple test result
        process_info = ProcessInfo(
            pid=1234,
            name="test_process",
            status="running",
            cmdline="test command",
            exe="/usr/bin/test",
            cwd="/tmp",
            environ={},
            connections=[],
            open_files=[],
            memory_maps=[],
            shared_libraries={
                'total_count': 0,
                'system_libraries': [],
                'user_libraries': [],
                'language_specific': [],
                'unique_directories': []
            }
        )
        
        result = AnalysisResult(process_info=process_info)
        
        # Test text formatter
        text_formatter = TextFormatter()
        text_output = text_formatter.format(result)
        assert "Process Analysis for PID 1234" in text_output
        print("✓ Text formatter works")
        
        # Test JSON formatter
        json_formatter = JSONFormatter()
        json_output = json_formatter.format(result)
        assert '"pid": 1234' in json_output
        print("✓ JSON formatter works")
        
        print("✅ Formatter tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Formatter test failed: {e}")
        return False

def test_config():
    """Test configuration system."""
    print("\nTesting configuration system...")
    
    try:
        from pid_analyzer.config.settings import Config
        
        # Test basic config
        config = Config()
        assert config.get('analyzers.java.detection_patterns.cmdline') is not None
        print("✓ Configuration loaded correctly")
        
        # Test analyzer config
        java_config = config.get_analyzer_config('java')
        assert 'detection_patterns' in java_config
        print("✓ Analyzer configuration works")
        
        print("✅ Configuration tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("PY-PID-ANALYZER Code Structure Tests")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_process_detection,
        test_formatters,
        test_config
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 60)
    print(f"Tests completed: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! Code reorganization successful!")
        return 0
    else:
        print("❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
