import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging():
    """
    Centralized logging setup function
    """
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Remove all existing handlers to avoid conflicts
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    
    # 1. Main application file handler with rotation
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    
    # 2. Traffic analyzer specific handler
    traffic_handler = RotatingFileHandler(
        'logs/traffic_analyzer.log',
        maxBytes=5*1024*1024,   # 5MB
        backupCount=3,
        encoding='utf-8'
    )
    traffic_handler.setLevel(logging.INFO)
    traffic_handler.setFormatter(formatter)
    
    # 3. Critical events handler (errors, warnings, critical)
    critical_handler = RotatingFileHandler(
        'logs/critical.log',
        maxBytes=2*1024*1024,   # 2MB
        backupCount=2,
        encoding='utf-8'
    )
    critical_handler.setLevel(logging.WARNING)
    critical_handler.setFormatter(formatter)
    
    # 4. Console handler for development
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s - %(name)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Set up root logger
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(critical_handler)
    root_logger.addHandler(console_handler)
    
    # Set up traffic analyzer logger
    traffic_logger = logging.getLogger("TrafficAnalyzer")
    traffic_logger.setLevel(logging.INFO)
    traffic_logger.addHandler(traffic_handler)
    traffic_logger.addHandler(console_handler)
    
    # Set up Flask logger
    flask_logger = logging.getLogger("werkzeug")
    flask_logger.setLevel(logging.WARNING)  # Reduce Flask noise
    
    return logging.getLogger("TrafficAnalyzer")