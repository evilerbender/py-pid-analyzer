"""
Output handlers for different destination types.
"""

import smtplib
from abc import ABC, abstractmethod
from email.mime.text import MIMEText
from typing import Any

from .formatters import OutputFormatter


class OutputHandler(ABC):
    """Base class for output handlers."""
    
    def __init__(self, formatter: OutputFormatter):
        self.formatter = formatter
    
    @abstractmethod
    def output(self, analysis_result: Any, **kwargs):
        """Output the analysis result."""
        pass


class StdoutHandler(OutputHandler):
    """Output to stdout."""
    
    def output(self, analysis_result: Any, **kwargs):
        """Output to stdout."""
        content = self.formatter.format(analysis_result)
        print(content)


class FileHandler(OutputHandler):
    """Output to filesystem."""
    
    def output(self, analysis_result: Any, file_path: str, **kwargs):
        """Output to file."""
        content = self.formatter.format(analysis_result)
        with open(file_path, 'w') as f:
            f.write(content)


class S3Handler(OutputHandler):
    """Output to AWS S3."""
    
    def output(self, analysis_result: Any, s3_uri: str, **kwargs):
        """Output to S3."""
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 is required for S3 output")
        
        content = self.formatter.format(analysis_result)
        s3 = boto3.client('s3')
        bucket, key = s3_uri.replace('s3://', '').split('/', 1)
        s3.put_object(Bucket=bucket, Key=key, Body=content)


class SMTPHandler(OutputHandler):
    """Output via SMTP email."""
    
    def output(self, analysis_result: Any, smtp_server: str, smtp_port: int,
               smtp_user: str, smtp_pass: str, smtp_to: str, smtp_from: str,
               pid: int, **kwargs):
        """Output via SMTP."""
        content = self.formatter.format(analysis_result)
        
        msg = MIMEText(content)
        msg['Subject'] = f'Process Analysis - PID {pid}'
        msg['From'] = smtp_from
        msg['To'] = smtp_to
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)


class CloudWatchHandler(OutputHandler):
    """Output to AWS CloudWatch Logs."""
    
    def output(self, analysis_result: Any, log_group: str, log_stream: str, **kwargs):
        """Output to CloudWatch Logs."""
        try:
            import boto3
            import time
        except ImportError:
            raise ImportError("boto3 is required for CloudWatch output")
        
        content = self.formatter.format(analysis_result)
        logs = boto3.client('logs')
        logs.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[{'timestamp': int(time.time() * 1000), 'message': content}]
        )
