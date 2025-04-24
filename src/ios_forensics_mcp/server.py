# server.py - Main MCP server implementation
import os
import sys
import json
import logging
from typing import Any, Dict, List, Optional, Union

# Import the FastMCP class
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("Error: MCP SDK not found. Please install with:")
    print("uv add \"mcp[cli]\"")
    sys.exit(1)

# Import utilities
from .utils.path_utils import (
    is_path_valid,
    normalize_path,
    get_absolute_path,
    is_file_readable
)
from .utils.logging_utils import setup_logging

# Import tools - import with renamed functions to avoid conflicts
from .tools.filesystem import directory
from .tools.filesystem import file_reader
from .tools.filesystem import file_type
from .tools.filesystem import search
from .tools.sqlite import analyzer
from .tools.plist import parser

# Import configuration directly - no fallbacks
import sys

# Direct import of the config module from the package
from .config_module import IOS_FILESYSTEM_ROOT, LOG_LEVEL, SERVER_PORT

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
        
        # Create FastMCP server
        self.mcp = FastMCP(
            "iOS Forensics Tools",
            version="0.1.0",
            description="Tools for forensic analysis of iOS file systems"
        )
        
        # Register all tools
        self._register_tools()
        
        logger.info(f"iOS Forensics MCP Server initialized with root: {self.ios_root}")
    
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
    
    def _register_tools(self):
        """Register all forensic tools with the MCP server"""
        
        # File System Tools
        @self.mcp.tool()
        def list_directory(path: str, recursive: bool = False, show_hidden: bool = False) -> Dict:
            """
            List contents of a directory in the iOS file system
            
            Args:
                path: Path relative to iOS root
                recursive: Whether to list directories recursively
                show_hidden: Whether to show hidden files
                
            Returns:
                Dictionary with directory contents
            """
            try:
                abs_path = self._validate_path(path)
                result = directory.list_directory(abs_path, recursive, show_hidden)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error listing directory {path}: {str(e)}")
                return {"success": False, "error": str(e)}
        
        @self.mcp.tool()
        def read_file(path: str, encoding: str = "auto", offset: int = 0, length: Optional[int] = None) -> Dict:
            """
            Read the contents of a file in the iOS file system
            
            Args:
                path: Path relative to iOS root
                encoding: File encoding (auto, utf-8, binary, etc.)
                offset: Starting byte offset
                length: Number of bytes to read
                
            Returns:
                Dictionary with file contents
            """
            try:
                abs_path = self._validate_path(path)
                if not is_file_readable(abs_path):
                    raise ValueError(f"File is not readable: {path}")
                
                result = file_reader.read_file(abs_path, encoding, offset, length)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error reading file {path}: {str(e)}")
                return {"success": False, "error": str(e)}
        
        @self.mcp.tool()
        def identify_file_type(path: str) -> Dict:
            """
            Identify the type of a file based on content
            
            Args:
                path: Path relative to iOS root
                
            Returns:
                Dictionary with file type information
            """
            try:
                abs_path = self._validate_path(path)
                result = file_type.identify_file_type(abs_path)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error identifying file type for {path}: {str(e)}")
                return {"success": False, "error": str(e)}
        
        @self.mcp.tool()
        def search_files(base_path: str, pattern: str, search_type: str = "filename") -> Dict:
            """
            Search for files in the iOS file system
            
            Args:
                base_path: Base path relative to iOS root
                pattern: Search pattern
                search_type: Type of search (filename, content, regex)
                
            Returns:
                Dictionary with search results
            """
            try:
                abs_path = self._validate_path(base_path)
                result = search.search_files(abs_path, pattern, search_type)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error searching files in {base_path}: {str(e)}")
                return {"success": False, "error": str(e)}
        
        # SQLite Database Tools
        @self.mcp.tool()
        def find_databases(base_path: Optional[str] = None) -> Dict:
            """
            Find SQLite databases in the iOS file system
            
            Args:
                base_path: Base path relative to iOS root (optional)
                
            Returns:
                Dictionary with database information
            """
            try:
                if base_path:
                    abs_path = self._validate_path(base_path)
                else:
                    abs_path = self.ios_root
                
                result = analyzer.find_databases(abs_path)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error finding databases: {str(e)}")
                return {"success": False, "error": str(e)}
        
        @self.mcp.tool()
        def analyze_schema(db_path: str) -> Dict:
            """
            Analyze the schema of a SQLite database
            
            Args:
                db_path: Path to the SQLite database relative to iOS root
                
            Returns:
                Dictionary with schema information
            """
            try:
                abs_path = self._validate_path(db_path)
                result = analyzer.analyze_schema(abs_path)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error analyzing schema for {db_path}: {str(e)}")
                return {"success": False, "error": str(e)}
        
        @self.mcp.tool()
        def execute_query(db_path: str, query: str, params: Optional[str] = None) -> Dict:
            """
            Execute a SQL query against a SQLite database
            
            Args:
                db_path: Path to the SQLite database relative to iOS root
                query: SQL query to execute
                params: Query parameters (JSON)
                
            Returns:
                Dictionary with query results
            """
            try:
                abs_path = self._validate_path(db_path)
                
                # Parse parameters if provided
                query_params = None
                if params:
                    try:
                        query_params = json.loads(params)
                    except json.JSONDecodeError:
                        raise ValueError("Invalid JSON format for query parameters")
                
                result = analyzer.execute_query(abs_path, query, query_params)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error executing query on {db_path}: {str(e)}")
                return {"success": False, "error": str(e)}
        
        # Plist Tools
        @self.mcp.tool()
        def parse_plist(plist_path: str) -> Dict:
            """
            Parse a property list file
            
            Args:
                plist_path: Path to the plist file relative to iOS root
                
            Returns:
                Dictionary with parsed plist content
            """
            try:
                abs_path = self._validate_path(plist_path)
                result = parser.parse_plist(abs_path)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error parsing plist {plist_path}: {str(e)}")
                return {"success": False, "error": str(e)}
        
        @self.mcp.tool()
        def query_plist(plist_path: str, query_path: str) -> Dict:
            """
            Query values from a property list file
            
            Args:
                plist_path: Path to the plist file relative to iOS root
                query_path: Query path (e.g., 'root.device.name')
                
            Returns:
                Dictionary with query results
            """
            try:
                abs_path = self._validate_path(plist_path)
                result = parser.query_plist(abs_path, query_path)
                return {"success": True, "data": result}
            except Exception as e:
                logger.error(f"Error querying plist {plist_path}: {str(e)}")
                return {"success": False, "error": str(e)}
        
        logger.info("All forensic tools registered with MCP server")
    
    def start(self):
        """Start the MCP server"""
        logger.info(f"Starting iOS Forensics MCP Server on port {self.port}")
        self.mcp.run(port=self.port)


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