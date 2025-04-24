# config.py - Configuration settings for iOS Forensics MCP Server

import os
import json
import logging
from typing import Dict, List, Optional, Any
import argparse


# Default configuration values
DEFAULT_CONFIG = {
    # Server settings
    'server': {
        'port': 8080,
        'host': '127.0.0.1',
        'log_level': 'INFO',
        'max_concurrent_requests': 5,
    },
    
    # iOS file system settings
    'ios_filesystem': {
        'root_path': './ios_extraction',
        'read_only': True,  # Read-only mode for evidence preservation
        'allowed_paths': [
            'private/var/mobile/Library',
            'private/var/mobile/Containers',
            'private/var/mobile/Media',
            'private/var/root'
        ],
        'excluded_paths': [
            'private/var/mobile/Library/Caches'
        ]
    },
    
    # Tool settings
    'tools': {
        'filesystem': {
            'enabled': True,
            'max_file_size': 100 * 1024 * 1024,  # 100 MB max file size for reading
            'excluded_extensions': ['.ipa', '.app', '.zip', '.ipsw']
        },
        'sqlite': {
            'enabled': True,
            'use_temp_copy': True,  # Use a temporary copy for all operations
            'respect_wal': True,  # Handle WAL files properly
            'max_query_rows': 1000,  # Maximum rows to return from a query
            'max_query_time': 30  # Maximum query execution time in seconds
        },
        'plist': {
            'enabled': True,
            'max_plist_size': 10 * 1024 * 1024  # 10 MB max plist size
        },
        'specialized': {
            'enabled': True,
            'modules': {
                'messages': True,
                'calls': True,
                'contacts': True,
                'calendar': True,
                'photos': True,
                'notes': True,
                'browser': True,
                'locations': True,
                'health': True,
                'applications': True
            }
        },
        'advanced': {
            'enabled': True,
            'timeline_enabled': True,
            'carving_enabled': True,
            'reporting_enabled': True
        }
    },
    
    # Security settings
    'security': {
        'require_approval': False,  # Require approval for certain operations
        'approved_operations': [
            'list_directory',
            'read_file',
            'identify_file_type',
            'analyze_schema',
            'parse_plist'
        ],
        'approval_required_operations': [
            'execute_query',
            'search_files',
            'extract_deleted'
        ],
        'authentication_required': False,
        'api_key': None
    },
    
    # Logging settings
    'logging': {
        'file': 'ios_forensics_mcp.log',
        'max_size': 10 * 1024 * 1024,  # 10 MB
        'backup_count': 5,
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'console_level': 'INFO',
        'file_level': 'DEBUG'
    },
    
    # Performance settings
    'performance': {
        'cache_enabled': True,
        'cache_size': 100 * 1024 * 1024,  # 100 MB
        'cache_ttl': 3600,  # 1 hour
        'thread_pool_size': 4
    }
}


class Config:
    """
    Configuration manager for the iOS Forensics MCP Server.
    
    Handles loading, saving, and accessing configuration settings.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Optional path to a configuration file
        """
        self.config_path = config_path
        self.config = DEFAULT_CONFIG.copy()
        
        # Load config from file if specified
        if config_path and os.path.exists(config_path):
            self.load_from_file(config_path)
        
        # Override from environment variables
        self._override_from_env()
        
        # Override from command line arguments
        self._override_from_args()
    
    def load_from_file(self, config_path: str) -> None:
        """
        Load configuration from a JSON file.
        
        Args:
            config_path: Path to the configuration file
        """
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
            
            # Recursively update the default config with values from the file
            self._update_nested_dict(self.config, file_config)
            
            logging.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logging.error(f"Error loading configuration from {config_path}: {e}")
    
    def save_to_file(self, config_path: Optional[str] = None) -> None:
        """
        Save the current configuration to a JSON file.
        
        Args:
            config_path: Path to save the configuration file (defaults to self.config_path)
        """
        path = config_path or self.config_path
        if not path:
            logging.error("No configuration path specified")
            return
        
        try:
            with open(path, 'w') as f:
                json.dump(self.config, f, indent=4)
            
            logging.info(f"Saved configuration to {path}")
        except Exception as e:
            logging.error(f"Error saving configuration to {path}: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key.
        
        Args:
            key: Dot-separated path to the configuration value (e.g., 'server.port')
            default: Default value to return if the key is not found
            
        Returns:
            The configuration value or the default
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value by key.
        
        Args:
            key: Dot-separated path to the configuration value (e.g., 'server.port')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        # Navigate to the nested dictionary
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
    
    def get_all(self) -> Dict:
        """
        Get the entire configuration dictionary.
        
        Returns:
            The configuration dictionary
        """
        return self.config
    
    def _update_nested_dict(self, d: Dict, u: Dict) -> Dict:
        """
        Recursively update a nested dictionary.
        
        Args:
            d: Dictionary to update
            u: Dictionary with updates
            
        Returns:
            Updated dictionary
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                d[k] = self._update_nested_dict(d[k], v)
            else:
                d[k] = v
        return d
    
    def _override_from_env(self) -> None:
        """Override configuration values from environment variables."""
        # Server settings
        if 'IOS_FORENSICS_PORT' in os.environ:
            try:
                self.config['server']['port'] = int(os.environ['IOS_FORENSICS_PORT'])
            except ValueError:
                pass
        
        if 'IOS_FORENSICS_HOST' in os.environ:
            self.config['server']['host'] = os.environ['IOS_FORENSICS_HOST']
        
        if 'IOS_FORENSICS_LOG_LEVEL' in os.environ:
            self.config['server']['log_level'] = os.environ['IOS_FORENSICS_LOG_LEVEL']
        
        # iOS file system settings
        if 'IOS_FORENSICS_ROOT_PATH' in os.environ:
            self.config['ios_filesystem']['root_path'] = os.environ['IOS_FORENSICS_ROOT_PATH']
        
        if 'IOS_FORENSICS_READ_ONLY' in os.environ:
            self.config['ios_filesystem']['read_only'] = os.environ['IOS_FORENSICS_READ_ONLY'].lower() in ('true', 'yes', '1')
        
        # Security settings
        if 'IOS_FORENSICS_REQUIRE_APPROVAL' in os.environ:
            self.config['security']['require_approval'] = os.environ['IOS_FORENSICS_REQUIRE_APPROVAL'].lower() in ('true', 'yes', '1')
        
        if 'IOS_FORENSICS_API_KEY' in os.environ:
            self.config['security']['api_key'] = os.environ['IOS_FORENSICS_API_KEY']
            self.config['security']['authentication_required'] = True
    
    def _override_from_args(self) -> None:
        """Override configuration values from command line arguments."""
        parser = argparse.ArgumentParser(description='iOS Forensics MCP Server')
        
        parser.add_argument('--port', type=int, help='Server port')
        parser.add_argument('--host', help='Server host')
        parser.add_argument('--log-level', help='Logging level')
        parser.add_argument('--root-path', help='iOS file system root path')
        parser.add_argument('--read-only', type=bool, help='Read-only mode')
        parser.add_argument('--config', help='Path to configuration file')
        
        args = parser.parse_args()
        
        # Load config from file if specified
        if args.config and os.path.exists(args.config):
            self.load_from_file(args.config)
        
        # Override with command line arguments
        if args.port:
            self.config['server']['port'] = args.port
        
        if args.host:
            self.config['server']['host'] = args.host
        
        if args.log_level:
            self.config['server']['log_level'] = args.log_level
        
        if args.root_path:
            self.config['ios_filesystem']['root_path'] = args.root_path
        
        if args.read_only is not None:
            self.config['ios_filesystem']['read_only'] = args.read_only


# Create a global configuration instance
CONFIG = Config()

# Export configuration values
SERVER_PORT = CONFIG.get('server.port')
SERVER_HOST = CONFIG.get('server.host')
LOG_LEVEL = CONFIG.get('server.log_level')
IOS_FILESYSTEM_ROOT = CONFIG.get('ios_filesystem.root_path')
READ_ONLY_MODE = CONFIG.get('ios_filesystem.read_only')
ALLOWED_PATHS = CONFIG.get('ios_filesystem.allowed_paths')
EXCLUDED_PATHS = CONFIG.get('ios_filesystem.excluded_paths')
MAX_FILE_SIZE = CONFIG.get('tools.filesystem.max_file_size')
USE_TEMP_COPY = CONFIG.get('tools.sqlite.use_temp_copy')
RESPECT_WAL = CONFIG.get('tools.sqlite.respect_wal')
MAX_QUERY_ROWS = CONFIG.get('tools.sqlite.max_query_rows')
REQUIRE_APPROVAL = CONFIG.get('security.require_approval')
APPROVED_OPERATIONS = CONFIG.get('security.approved_operations')
APPROVAL_REQUIRED_OPERATIONS = CONFIG.get('security.approval_required_operations')
AUTHENTICATION_REQUIRED = CONFIG.get('security.authentication_required')
API_KEY = CONFIG.get('security.api_key')
CACHE_ENABLED = CONFIG.get('performance.cache_enabled')
CACHE_SIZE = CONFIG.get('performance.cache_size')
THREAD_POOL_SIZE = CONFIG.get('performance.thread_pool_size')


def setup_logging() -> logging.Logger:
    """
    Set up logging based on configuration.
    
    Returns:
        Logger instance
    """
    log_config = CONFIG.get('logging')
    
    # Create logger
    logger = logging.getLogger('ios_forensics_mcp')
    logger.setLevel(logging.DEBUG)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_config['console_level']))
    
    # Create file handler
    file_handler = logging.FileHandler(log_config['file'])
    file_handler.setLevel(getattr(logging, log_config['file_level']))
    
    # Create formatter
    formatter = logging.Formatter(log_config['format'])
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger


# Set up logging
LOGGER = setup_logging()
