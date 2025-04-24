# utils/logging_utils.py - Logging utilities for iOS Forensics MCP Server

import logging
import os
import sys
from typing import Optional

def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """
    Set up logging with the specified log level
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger instance
    """
    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Create and configure logger for our module
    logger = logging.getLogger('ios_forensics_mcp')
    logger.setLevel(numeric_level)
    
    # Create file handler if log directory exists
    log_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError:
            pass  # Ignore if can't create log directory
    
    if os.path.exists(log_dir):
        log_file = os.path.join(log_dir, 'ios_forensics_mcp.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger