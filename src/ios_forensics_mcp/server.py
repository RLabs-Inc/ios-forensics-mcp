# server.py - Main MCP server implementation

import os
import sys
import json
import logging
from typing import Any, Dict, List, Optional, Union

# Import MCP SDK
try:
    from modelcontextprotocol.server import MCPServer
    from modelcontextprotocol.function import Function, Parameter, ParameterType
except ImportError:
    print("Error: Model Context Protocol SDK not found. Please install with:")
    print("uv add modelcontextprotocol")
    sys.exit(1)

# Import utilities
from .utils.path_utils import (
    is_path_valid,
    normalize_path,
    get_absolute_path,
    is_file_readable
)
from .utils.logging_utils import setup_logging

# Import tools
from .tools.filesystem.directory import list_directory
from .tools.filesystem.file_reader import read_file
from .tools.filesystem.file_type import identify_file_type
from .tools.filesystem.search import search_files
from .tools.sqlite.analyzer import find_databases, analyze_schema, execute_query
from .tools.plist.parser import parse_plist, query_plist

# Configuration - dynamically import from root directory
import importlib.util
import pathlib

# Dynamically import config.py from the root directory
config_path = pathlib.Path(__file__).parent.parent.parent / "config.py"
spec = importlib.util.spec_from_file_location("config", config_path)
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)

# Get the required variables from config
IOS_FILESYSTEM_ROOT = config.IOS_FILESYSTEM_ROOT
LOG_LEVEL = config.LOG_LEVEL
SERVER_PORT = config.SERVER_PORT

# Setup logging
logger = setup_logging(LOG_LEVEL)

class IOSForensicsMCPServer:
    """
    MCP Server for iOS Forensics Analysis
    
    This server provides tools for analyzing an extracted iOS file system
    through the Model Context Protocol.
    """
    
    def __init__(self, ios_root: str, port: int = 8080):
        """
        Initialize the iOS Forensics MCP Server
        
        Args:
            ios_root: Root directory of the extracted iOS file system
            port: Port to run the MCP server on
        """
        self.ios_root = os.path.abspath(ios_root)
        if not os.path.isdir(self.ios_root):
            raise ValueError(f"iOS root directory does not exist: {self.ios_root}")
        
        self.port = port
        self.server = MCPServer()
        
        # Register all tools
        self._register_tools()
        
        logger.info(f"iOS Forensics MCP Server initialized with root: {self.ios_root}")
    
    def _register_tools(self):
        """Register all forensic tools with the MCP server"""
        
        # File System Tools
        self.server.register_function(
            Function(
                name="list_directory",
                description="List contents of a directory in the iOS file system",
                parameters=[
                    Parameter(
                        name="path",
                        description="Path relative to iOS root",
                        type=ParameterType.STRING,
                        required=True
                    ),
                    Parameter(
                        name="recursive",
                        description="Whether to list directories recursively",
                        type=ParameterType.BOOLEAN,
                        required=False
                    ),
                    Parameter(
                        name="show_hidden",
                        description="Whether to show hidden files",
                        type=ParameterType.BOOLEAN,
                        required=False
                    )
                ],
                handler=self._handle_list_directory
            )
        )
        
        self.server.register_function(
            Function(
                name="read_file",
                description="Read the contents of a file in the iOS file system",
                parameters=[
                    Parameter(
                        name="path",
                        description="Path relative to iOS root",
                        type=ParameterType.STRING,
                        required=True
                    ),
                    Parameter(
                        name="encoding",
                        description="File encoding (auto, utf-8, binary, etc.)",
                        type=ParameterType.STRING,
                        required=False
                    ),
                    Parameter(
                        name="offset",
                        description="Starting byte offset",
                        type=ParameterType.INTEGER,
                        required=False
                    ),
                    Parameter(
                        name="length",
                        description="Number of bytes to read",
                        type=ParameterType.INTEGER,
                        required=False
                    )
                ],
                handler=self._handle_read_file
            )
        )
        
        self.server.register_function(
            Function(
                name="identify_file_type",
                description="Identify the type of a file based on content",
                parameters=[
                    Parameter(
                        name="path",
                        description="Path relative to iOS root",
                        type=ParameterType.STRING,
                        required=True
                    )
                ],
                handler=self._handle_identify_file_type
            )
        )
        
        self.server.register_function(
            Function(
                name="search_files",
                description="Search for files in the iOS file system",
                parameters=[
                    Parameter(
                        name="base_path",
                        description="Base path relative to iOS root",
                        type=ParameterType.STRING,
                        required=True
                    ),
                    Parameter(
                        name="pattern",
                        description="Search pattern",
                        type=ParameterType.STRING,
                        required=True
                    ),
                    Parameter(
                        name="search_type",
                        description="Type of search (filename, content, regex)",
                        type=ParameterType.STRING,
                        required=False
                    )
                ],
                handler=self._handle_search_files
            )
        )
        
        # SQLite Database Tools
        self.server.register_function(
            Function(
                name="find_databases",
                description="Find SQLite databases in the iOS file system",
                parameters=[
                    Parameter(
                        name="base_path",
                        description="Base path relative to iOS root",
                        type=ParameterType.STRING,
                        required=False
                    )
                ],
                handler=self._handle_find_databases
            )
        )
        
        self.server.register_function(
            Function(
                name="analyze_schema",
                description="Analyze the schema of a SQLite database",
                parameters=[
                    Parameter(
                        name="db_path",
                        description="Path to the SQLite database relative to iOS root",
                        type=ParameterType.STRING,
                        required=True
                    )
                ],
                handler=self._handle_analyze_schema
            )
        )
        
        self.server.register_function(
            Function(
                name="execute_query",
                description="Execute a SQL query against a SQLite database",
                parameters=[
                    Parameter(
                        name="db_path",
                        description="Path to the SQLite database relative to iOS root",
                        type=ParameterType.STRING,
                        required=True
                    ),
                    Parameter(
                        name="query",
                        description="SQL query to execute",
                        type=ParameterType.STRING,
                        required=True
                    ),
                    Parameter(
                        name="params",
                        description="Query parameters (JSON)",
                        type=ParameterType.STRING,
                        required=False
                    )
                ],
                handler=self._handle_execute_query
            )
        )
        
        # Plist Tools
        self.server.register_function(
            Function(
                name="parse_plist",
                description="Parse a property list file",
                parameters=[
                    Parameter(
                        name="plist_path",
                        description="Path to the plist file relative to iOS root",
                        type=ParameterType.STRING,
                        required=True
                    )
                ],
                handler=self._handle_parse_plist
            )
        )
        
        self.server.register_function(
            Function(
                name="query_plist",
                description="Query values from a property list file",
                parameters=[
                    Parameter(
                        name="plist_path",
                        description="Path to the plist file relative to iOS root",
                        type=ParameterType.STRING,
                        required=True
                    ),
                    Parameter(
                        name="query_path",
                        description="Query path (e.g., 'root.device.name')",
                        type=ParameterType.STRING,
                        required=True
                    )
                ],
                handler=self._handle_query_plist
            )
        )
        
        # Register more tools here...
        
        logger.info("All forensic tools registered with MCP server")
    
    def _validate_path(self, path: str) -> str:
        """
        Validate and normalize a path within the iOS file system
        
        Args:
            path: Path relative to iOS root
            
        Returns:
            Absolute path if valid
            
        Raises:
            ValueError: If path is invalid or outside iOS root
        """
        norm_path = normalize_path(path)
        abs_path = get_absolute_path(self.ios_root, norm_path)
        
        if not is_path_valid(abs_path, self.ios_root):
            raise ValueError(f"Invalid path: {path}")
        
        return abs_path
    
    # Handler implementations
    
    def _handle_list_directory(self, path: str, recursive: bool = False, show_hidden: bool = False) -> Dict:
        """Handle list_directory function calls"""
        try:
            abs_path = self._validate_path(path)
            result = list_directory(abs_path, recursive, show_hidden)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error listing directory {path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _handle_read_file(self, path: str, encoding: str = "auto", offset: int = 0, length: Optional[int] = None) -> Dict:
        """Handle read_file function calls"""
        try:
            abs_path = self._validate_path(path)
            if not is_file_readable(abs_path):
                raise ValueError(f"File is not readable: {path}")
            
            result = read_file(abs_path, encoding, offset, length)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error reading file {path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _handle_identify_file_type(self, path: str) -> Dict:
        """Handle identify_file_type function calls"""
        try:
            abs_path = self._validate_path(path)
            result = identify_file_type(abs_path)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error identifying file type for {path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _handle_search_files(self, base_path: str, pattern: str, search_type: str = "filename") -> Dict:
        """Handle search_files function calls"""
        try:
            abs_path = self._validate_path(base_path)
            result = search_files(abs_path, pattern, search_type)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error searching files in {base_path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _handle_find_databases(self, base_path: Optional[str] = None) -> Dict:
        """Handle find_databases function calls"""
        try:
            if base_path:
                abs_path = self._validate_path(base_path)
            else:
                abs_path = self.ios_root
            
            result = find_databases(abs_path)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error finding databases: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _handle_analyze_schema(self, db_path: str) -> Dict:
        """Handle analyze_schema function calls"""
        try:
            abs_path = self._validate_path(db_path)
            result = analyze_schema(abs_path)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error analyzing schema for {db_path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _handle_execute_query(self, db_path: str, query: str, params: Optional[str] = None) -> Dict:
        """Handle execute_query function calls"""
        try:
            abs_path = self._validate_path(db_path)
            
            # Parse parameters if provided
            query_params = None
            if params:
                try:
                    query_params = json.loads(params)
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON format for query parameters")
            
            result = execute_query(abs_path, query, query_params)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error executing query on {db_path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _handle_parse_plist(self, plist_path: str) -> Dict:
        """Handle parse_plist function calls"""
        try:
            abs_path = self._validate_path(plist_path)
            result = parse_plist(abs_path)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error parsing plist {plist_path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _handle_query_plist(self, plist_path: str, query_path: str) -> Dict:
        """Handle query_plist function calls"""
        try:
            abs_path = self._validate_path(plist_path)
            result = query_plist(abs_path, query_path)
            return {"success": True, "data": result}
        except Exception as e:
            logger.error(f"Error querying plist {plist_path}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def start(self):
        """Start the MCP server"""
        logger.info(f"Starting iOS Forensics MCP Server on port {self.port}")
        self.server.start(port=self.port)


# Main entry point
if __name__ == "__main__":
    if len(sys.argv) > 1:
        ios_root = sys.argv[1]
    else:
        ios_root = IOS_FILESYSTEM_ROOT
    
    try:
        server = IOSForensicsMCPServer(ios_root, SERVER_PORT)
        server.start()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Error starting server: {str(e)}")
        sys.exit(1)
