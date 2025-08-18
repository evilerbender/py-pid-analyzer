"""
Main CLI interface for the process analyzer.
"""

import argparse
import os
import subprocess
import sys
from typing import Optional

from .core.analyzer import ProcessAnalyzer
from .core.process_detection import (
    is_java_process, is_webserver_process, is_redis_process, is_systemd_managed_process
)
from .ui.interactive import ProcessSelector
from .output.formatters import TextFormatter, JSONFormatter
from .output.handlers import (
    StdoutHandler, FileHandler, S3Handler, SMTPHandler, CloudWatchHandler
)


def create_output_handler(args, formatter):
    """Create appropriate output handler based on arguments."""
    if args.output == 'stdout':
        return StdoutHandler(formatter)
    elif args.output == 's3':
        return S3Handler(formatter)
    elif args.output == 'file':
        return FileHandler(formatter)
    elif args.output == 'smtp':
        return SMTPHandler(formatter)
    elif args.output == 'cloudwatch':
        return CloudWatchHandler(formatter)
    else:
        raise ValueError(f"Unknown output method: {args.output}")


def output_analysis(result, args):
    """Output analysis results based on specified method."""
    # Choose formatter
    formatter = JSONFormatter() if hasattr(args, 'format') and args.format == 'json' else TextFormatter()
    
    # Create handler
    handler = create_output_handler(args, formatter)
    
    # Output with appropriate parameters
    if args.output == 'stdout':
        handler.output(result)
    elif args.output == 's3':
        handler.output(result, s3_uri=args.s3_uri)
    elif args.output == 'file':
        handler.output(result, file_path=args.file_path)
    elif args.output == 'smtp':
        handler.output(
            result, 
            smtp_server=args.smtp_server,
            smtp_port=args.smtp_port,
            smtp_user=args.smtp_user,
            smtp_pass=args.smtp_pass,
            smtp_to=args.smtp_to,
            smtp_from=args.smtp_from,
            pid=result.process_info.pid
        )
    elif args.output == 'cloudwatch':
        handler.output(result, log_group=args.log_group, log_stream=args.log_stream)


def check_enhanced_analysis_needed(pid: int, args) -> bool:
    """Check if enhanced analysis should be performed."""
    if args.non_interactive:
        return False
    
    try:
        analyzer = ProcessAnalyzer(pid)
        info = analyzer._get_basic_info()
        
        # Check for specialized processes and prompt for enhanced analysis
        if is_java_process(info):
            try:
                from .analyzers.java import JavaAnalyzer
                java_analyzer = JavaAnalyzer(analyzer.process)
                app_type = java_analyzer._identify_java_app_type(info)
                response = input(f"\nDetected Java application ({app_type}). Include enhanced Java analysis? (y/N): ")
                return response.lower() in ['y', 'yes']
            except ImportError:
                pass
        elif is_webserver_process(info):
            try:
                from .analyzers.webserver import WebServerAnalyzer
                webserver_analyzer = WebServerAnalyzer(analyzer.process)
                server_type = webserver_analyzer._identify_webserver_type(info)
                response = input(f"\nDetected web server ({server_type}). Include enhanced web server analysis? (y/N): ")
                return response.lower() in ['y', 'yes']
            except ImportError:
                pass
        elif is_redis_process(info):
            if not args.non_interactive:
                print(f"\nDetected Redis server process. Including Redis analysis automatically.")
            return True
        
        # Inform user about automatic systemd analysis inclusion
        if is_systemd_managed_process(info):
            try:
                from .analyzers.systemd import SystemdAnalyzer
                systemd_analyzer = SystemdAnalyzer(analyzer.process)
                service_name = systemd_analyzer._detect_systemd_service_name(info)
                service_display = f" ({service_name})" if service_name else ""
                print(f"\nDetected systemd-managed process{service_display}. Including systemd analysis automatically.")
            except:
                pass
            return True
        
        return False
    except Exception:
        return False


def handle_privilege_escalation(args) -> bool:
    """Handle privilege escalation if needed."""
    if os.geteuid() != 0:
        if args.non_interactive:
            print("Error: Root privileges required. Run with sudo.", file=sys.stderr)
            return False
        
        response = input("Root privileges required for complete analysis. Escalate permissions? (y/N): ")
        if response.lower() in ['y', 'yes']:
            try:
                # Preserve the selected PID when escalating
                escalated_args = sys.argv.copy()
                if args.pid and str(args.pid) not in escalated_args:
                    escalated_args.append(str(args.pid))
                subprocess.run(['sudo', sys.executable] + escalated_args, check=True)
                return False  # Exit this process since we escalated
            except subprocess.CalledProcessError:
                print("Failed to escalate privileges", file=sys.stderr)
                return False
        else:
            print("Continuing with limited analysis...", file=sys.stderr)
    
    return True


def get_pid_from_user(args) -> Optional[int]:
    """Get PID from user input or interactive selection."""
    # Detect if we're in an interactive terminal session
    is_interactive_terminal = sys.stdin.isatty() and sys.stdout.isatty()
    
    # Handle missing PID - automatically go interactive if in terminal
    if args.pid is None and not args.non_interactive:
        if is_interactive_terminal:
            # Automatically start interactive mode in terminal sessions
            print("No PID specified. Starting interactive process selection...")
            selector = ProcessSelector()
            return selector.select_process_interactive()
        else:
            # In non-terminal environments, still prompt
            response = input("No PID specified. Select process interactively? (y/N): ")
            if response.lower() in ['y', 'yes']:
                selector = ProcessSelector()
                return selector.select_process_interactive()
            else:
                print("Error: PID required", file=sys.stderr)
                return None
    elif args.pid is None:
        print("Error: PID required in non-interactive mode", file=sys.stderr)
        return None
    
    return args.pid


def create_argument_parser():
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(description='Analyze a process by PID')
    parser.add_argument('pid', type=int, nargs='?', help='Process ID to analyze')
    parser.add_argument('--non-interactive', action='store_true', help='Run without prompts (fails if not root)')
    
    # Output options
    parser.add_argument('--output', choices=['stdout', 's3', 'file', 'smtp', 'cloudwatch'], 
                       default='stdout', help='Output method')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    
    # Output-specific arguments
    parser.add_argument('--s3-uri', help='S3 URI (s3://bucket/key)')
    parser.add_argument('--file-path', help='Filesystem path')
    parser.add_argument('--smtp-server', help='SMTP server')
    parser.add_argument('--smtp-port', type=int, default=587, help='SMTP port')
    parser.add_argument('--smtp-user', help='SMTP username')
    parser.add_argument('--smtp-pass', help='SMTP password')
    parser.add_argument('--smtp-to', help='Email recipient')
    parser.add_argument('--smtp-from', help='Email sender')
    parser.add_argument('--log-group', help='CloudWatch log group name')
    parser.add_argument('--log-stream', help='CloudWatch log stream name')
    
    return parser


def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Get PID from user
    pid = get_pid_from_user(args)
    if pid is None:
        sys.exit(1)
    args.pid = pid
    
    # Handle privilege escalation
    if not handle_privilege_escalation(args):
        sys.exit(0)
    
    try:
        # Create analyzer and perform analysis
        analyzer = ProcessAnalyzer(args.pid)
        
        # Check if enhanced analysis is needed
        enhanced = check_enhanced_analysis_needed(args.pid, args)
        
        # Perform analysis
        result = analyzer.analyze(enhanced=enhanced)
        
        # Output results
        output_analysis(result, args)
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAnalysis interrupted", file=sys.stderr)
        sys.exit(1)
    except ImportError as e:
        print(f"Import error: {e}", file=sys.stderr)
        print("Please ensure all required dependencies are installed.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
