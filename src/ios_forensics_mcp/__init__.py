# Import necessary modules
import sys
import os
import pathlib

# Import configuration module directly
from .config_module import IOS_FILESYSTEM_ROOT, SERVER_PORT

def main() -> None:
    """
    Entry point for the iOS Forensics MCP Server.
    This function is called when running the package with 'uv run ios-forensics-mcp'.
    """
    # Import server class here to avoid circular imports
    from .server import IOSForensicsMCPServer
    
    # Get iOS root directory from command line arguments or config
    if len(sys.argv) > 1:
        ios_root = sys.argv[1]
    else:
        ios_root = IOS_FILESYSTEM_ROOT
    
    try:
        # Initialize and start the server
        server = IOSForensicsMCPServer(ios_root, SERVER_PORT)
        server.start()
    except KeyboardInterrupt:
        print("Server stopped by user")
    except Exception as e:
        print(f"Error starting server: {str(e)}")
        sys.exit(1)

# This allows the module to be executed directly
if __name__ == "__main__":
    main()