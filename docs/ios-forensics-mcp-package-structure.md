# iOS Forensics MCP Server: Package Structure

## Directory Structure

```
ios_forensics_mcp/
├── pyproject.toml              # Project metadata and dependencies
├── README.md                   # Project documentation
├── requirements.txt            # Dependencies list
├── setup.py                    # Package setup script
├── config.json                 # Default configuration file
├── server.py                   # Main MCP server entry point
├── config.py                   # Configuration management
│
├── ios_forensics_mcp/          # Main package directory
│   ├── __init__.py             # Package initialization
│   │
│   ├── tools/                  # Tool implementations
│   │   ├── __init__.py
│   │   │
│   │   ├── filesystem/         # File system tools
│   │   │   ├── __init__.py
│   │   │   ├── directory.py    # Directory navigation tools
│   │   │   ├── file_reader.py  # File reading tools
│   │   │   ├── file_type.py    # File type identification
│   │   │   └── search.py       # File search tools
│   │   │
│   │   ├── sqlite/             # SQLite analysis tools
│   │   │   ├── __init__.py
│   │   │   ├── analyzer.py     # SQLite database analyzer
│   │   │   ├── wal_analyzer.py # WAL file analyzer
│   │   │   ├── freelist.py     # Freelist/deleted record recovery
│   │   │   └── carver.py       # SQLite database carver
│   │   │
│   │   ├── plist/              # Property List tools
│   │   │   ├── __init__.py
│   │   │   └── parser.py       # Plist parsing tools
│   │   │
│   │   ├── specialized/        # iOS-specific artifact parsers
│   │   │   ├── __init__.py
│   │   │   ├── messages.py     # Messages/iMessage analyzer
│   │   │   ├── calls.py        # Call history analyzer
│   │   │   ├── contacts.py     # Contacts analyzer
│   │   │   ├── calendar.py     # Calendar analyzer
│   │   │   ├── photos.py       # Photos database analyzer
│   │   │   ├── notes.py        # Notes analyzer
│   │   │   ├── browser.py      # Safari browser analyzer
│   │   │   ├── locations.py    # Location data analyzer
│   │   │   ├── health.py       # Health data analyzer
│   │   │   └── applications.py # App data analyzer
│   │   │
│   │   └── advanced/           # Advanced analysis tools
│   │       ├── __init__.py
│   │       ├── timeline.py     # Timeline generation
│   │       ├── entity.py       # Entity extraction
│   │       ├── pattern.py      # Pattern recognition
│   │       └── reporting.py    # Report generation
│   │
│   ├── models/                 # Data models
│   │   ├── __init__.py
│   │   ├── ios_schema.py       # iOS database schema definitions
│   │   └── artifact_maps.py    # Known artifact path mappings
│   │
│   └── utils/                  # Utility functions
│       ├── __init__.py
│       ├── path_utils.py       # Path validation and manipulation
│       ├── timestamp_utils.py  # Timestamp conversion utilities
│       └── logging_utils.py    # Logging utilities
│
└── tests/                      # Test cases
    ├── __init__.py
    ├── test_path_utils.py
    ├── test_sqlite_analyzer.py
    ├── test_plist_parser.py
    └── test_messages.py
```

## File Mapping

Here's where each of the files we've already created would go in the package structure:

| File Created | Location in Package |
|--------------|---------------------|
| server.py | ios_forensics_mcp/server.py |
| config.py | ios_forensics_mcp/config.py |
| utils/path_utils.py | ios_forensics_mcp/utils/path_utils.py |
| utils/timestamp_utils.py | ios_forensics_mcp/utils/timestamp_utils.py |
| tools/sqlite/analyzer.py | ios_forensics_mcp/tools/sqlite/analyzer.py |
| tools/sqlite/wal_analyzer.py | ios_forensics_mcp/tools/sqlite/wal_analyzer.py |
| tools/plist/parser.py | ios_forensics_mcp/tools/plist/parser.py |
| tools/specialized/messages.py | ios_forensics_mcp/tools/specialized/messages.py |
| tools/specialized/applications.py | ios_forensics_mcp/tools/specialized/applications.py |

## How to Install

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Or install from requirements
pip install -r requirements.txt
```

## How to Run

```bash
# Run the server directly
python server.py /path/to/ios_extraction

# Or with uv (efficient Python package installer and runner)
uv run server.py /path/to/ios_extraction

# Using the installed package
python -m ios_forensics_mcp.server /path/to/ios_extraction
```

## How to Add a New Tool

To extend this framework with a new tool:

1. Create a new module file in the appropriate directory
2. Implement your tool functions
3. Register the tool in `server.py`
4. Update `config.py` to include any tool-specific settings

For example, to add a new Photos analyzer:

1. Create `ios_forensics_mcp/tools/specialized/photos.py` with your analyzer functionality
2. Register the tool in `server.py` with the MCP server
3. Add any photos-specific configuration in `config.py`

## Requirements

The pyproject.toml would include:

```toml
[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "ios_forensics_mcp"
version = "0.1.0"
description = "iOS Forensics MCP Server for analyzing iPhone/iPad file systems"
readme = "README.md"
authors = [
    {name = "Your Name", email = "your.email@example.com"}
]
license = {text = "MIT"}
classifiers = [
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Topic :: Security",
    "Topic :: System :: Forensics",
]
requires-python = ">=3.9"
dependencies = [
    "modelcontextprotocol",
    "biplist",
    "python-magic",
    "pillow",
]

[project.optional-dependencies]
dev = [
    "pytest",
    "black",
    "isort",
    "mypy",
]
```
