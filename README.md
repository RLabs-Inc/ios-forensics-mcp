# iOS Forensics MCP Server

A forensic analysis server for iOS file systems using the Model Context Protocol (MCP). This project enables AI assistants like Claude to access and analyze extracted iOS file systems for digital forensics purposes.

## 🔍 Overview

The iOS Forensics MCP Server provides tools for analyzing iOS device extractions, focusing on:

- File system analysis
- SQLite database parsing with WAL forensics
- Property List (plist) parsing
- iOS artifact analysis (messages, call logs, contacts, locations, etc.)
- Timeline generation
- Forensic reporting

This is designed as an educational/learning tool, allowing users to interact with an AI assistant to explore and analyze iOS data.

## 🚀 Features

- **File System Tools**

  - Directory navigation with metadata analysis
  - File content viewing with type recognition
  - File searching with content and pattern matching

- **SQLite Analysis**

  - Database discovery and schema analysis
  - Secure query execution with WAL handling
  - Deleted record recovery from freelist pages
  - Database carving for deep forensic analysis

- **Plist Analysis**

  - Binary and XML plist parsing
  - Value extraction with query paths
  - Timestamp analysis

- **Specialized iOS Parsers**

  - Messages analyzer (SMS/iMessage)
  - Call log analyzer
  - Contacts analyzer
  - Location data analyzer
  - Browser history analyzer
  - Photo geolocation extractor
  - App data analyzer

- **Advanced Analysis**
  - Timeline generation across multiple data sources
  - Pattern recognition for user behavior analysis
  - Deleted data recovery
  - Comprehensive reporting

## 📋 Requirements

- Python 3.9+
- MCP compatible client (Claude Desktop, Claude Code, VS Code with MCP plugin, etc.)
- Extracted iOS file system (accessible directory)

## 📦 Installation

### Using uv

```bash
# Install using uv
uv install ios-forensics-mcp
```

### From source

```bash
# Clone the repository
git clone https://github.com/RLabs-Inc/ios-forensics-mcp.git
cd ios-forensics-mcp

# Install dependencies (automatically uses editable mode)
uv sync
```

## Claude Desktop Setup

Add the MCP server to your Claude Desktop configuration file (typically located at ~/.claude/config.json or similar path based on your OS):

```json
{
  "mcpServers": {
    "ios-forensics": {
      "command": "uv",
      "args": [
        "run",
        "ios-forensics-mcp",
        "--root-path",
        "/path/to/ios_extraction"
      ]
    }
  }
}
```

After adding this configuration, restart Claude Desktop, and the iOS Forensics MCP server will appear in your available servers list.

### Using with Claude

Once the server is running and configured with Claude, you can start asking forensic questions:

- "Can you show me the SMS messages from this device?"
- "Extract location data from this iPhone and create a timeline"
- "Analyze the call history and show me frequently contacted numbers"
- "Find deleted messages in the SMS database"
- "Generate a report of all activity on March 15th"
- "What apps are installed on this device?"
- "Show me the last known location of this device"
- "Extract photos and their geolocation data"
- "Analyze the browser history for suspicious activity"
- "Find all contacts with phone numbers"

## Claude Code Integration

To use iOS Forensics MCP with Claude Code, you need to add it as an MCP server. First ensure you have Claude Code installed:

```bash
# Install Claude Code if not already installed
npm install -g @anthropic-ai/claude-code
```

Then add the iOS Forensics MCP server to Claude Code:

```bash
# Add the MCP server to Claude Code
claude mcp add ios-forensics uv run ios-forensics-mcp --root-path /path/to/ios_extraction

# Or if you want to share with everyone in your project (creates .mcp.json)
claude mcp add ios-forensics -s project uv run ios-forensics-mcp --root-path /path/to/ios_extraction

# To verify the server was added
claude mcp get ios-forensics
```

You can also import this MCP server from Claude Desktop to Claude Code:

```bash
# Import servers from Claude Desktop
claude mcp add-from-claude-desktop
```

## 🔧 Configuration

Create a configuration file (config.json) to set up your iOS forensics environment:

```json
{
  "ios_filesystem": {
    "root_path": "/path/to/ios_extraction",
    "read_only": true
  },
  "server": {
    "port": 8080,
    "host": "127.0.0.1"
  }
}
```

## 🚀 Usage

### Starting the MCP Server

```bash
# Start with default config
ios-forensics-mcp

# Start with specific config file
ios-forensics-mcp --config /path/to/config.json

# Start with specific iOS root path
ios-forensics-mcp --root-path /path/to/ios_extraction
```

## 🗂️ Project Structure

```
ios_forensics_mcp/
├── tools/              # Tool implementations
│   ├── filesystem/     # File system tools
│   ├── sqlite/         # SQLite analysis tools
│   ├── plist/          # Property List tools
│   ├── specialized/    # iOS-specific artifact parsers
│   └── advanced/       # Advanced analysis tools
├── utils/              # Utility functions
├── models/             # Data models
└── tests/              # Test cases
```

## 📚 Documentation

For detailed documentation on each tool and its capabilities, see the [documentation](https://github.com/rlabs-inc/ios-forensics-mcp/docs).

## 🛡️ Security Considerations

This tool runs with the permissions of the user executing it and can access the file system accordingly. For security:

- Always run in read-only mode for evidence preservation
- Validate paths to prevent directory traversal
- Use a dedicated non-privileged user for running the server
- Restrict access to the extracted iOS file system

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Acknowledgements

- Thanks to the digital forensics community for research and documentation on iOS artifacts
- Thanks to the MCP community for creating the protocol that makes this tool possible
