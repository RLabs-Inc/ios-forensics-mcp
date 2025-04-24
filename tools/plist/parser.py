# tools/plist/parser.py - Property List parsing tools

import os
import plistlib
import biplist
import logging
import json
from typing import Any, Dict, List, Optional, Union

# Set up logging
logger = logging.getLogger(__name__)


def is_plist_file(file_path: str) -> bool:
    """
    Check if a file is a property list
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file is a property list, False otherwise
    """
    if not os.path.isfile(file_path):
        return False
    
    # Check extension
    _, ext = os.path.splitext(file_path)
    if ext.lower() in ['.plist', '.bplist']:
        return True
    
    # Check content
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)
        
        # Check for XML plist signature
        if header.startswith(b'<?xml') or header.startswith(b'<plist'):
            return True
        
        # Check for binary plist signature (bplist00)
        if header.startswith(b'bplist00'):
            return True
        
        return False
    except Exception as e:
        logger.error(f"Error checking plist header for {file_path}: {e}")
        return False


def parse_plist(plist_path: str) -> Dict:
    """
    Parse a property list file (XML or binary format)
    
    Args:
        plist_path: Path to the property list file
        
    Returns:
        Dictionary with parsed plist content
    """
    logger.info(f"Parsing plist: {plist_path}")
    
    if not os.path.isfile(plist_path):
        raise FileNotFoundError(f"File not found: {plist_path}")
    
    # Determine if this is a binary or XML plist
    is_binary = False
    with open(plist_path, 'rb') as f:
        header = f.read(8)
        is_binary = header.startswith(b'bplist')
    
    try:
        # First try with plistlib
        with open(plist_path, 'rb') as f:
            try:
                plist_data = plistlib.load(f)
                return _convert_plist_to_dict(plist_data)
            except Exception as e:
                logger.warning(f"plistlib failed to parse {plist_path}: {e}")
        
        # If plistlib fails and it's a binary plist, try biplist
        if is_binary:
            try:
                plist_data = biplist.readPlist(plist_path)
                return _convert_plist_to_dict(plist_data)
            except Exception as e:
                logger.warning(f"biplist failed to parse {plist_path}: {e}")
        
        # If all parsing methods fail, return error
        raise ValueError(f"Failed to parse plist file: {plist_path}")
    
    except Exception as e:
        logger.error(f"Error parsing plist {plist_path}: {e}")
        raise


def _convert_plist_to_dict(plist_data: Any) -> Dict:
    """
    Convert plist data to a dictionary with JSON-serializable values
    
    Args:
        plist_data: Parsed plist data
        
    Returns:
        Dictionary with converted values
    """
    if isinstance(plist_data, dict):
        return {str(k): _convert_plist_to_dict(v) for k, v in plist_data.items()}
    elif isinstance(plist_data, list):
        return [_convert_plist_to_dict(item) for item in plist_data]
    elif isinstance(plist_data, bytes):
        # Try to decode as UTF-8, fall back to hexadecimal
        try:
            return plist_data.decode('utf-8')
        except UnicodeDecodeError:
            return f"<binary data: {plist_data.hex()}>"
    elif isinstance(plist_data, (int, float, str, bool, type(None))):
        return plist_data
    else:
        # Handle other data types (like NSDate)
        return str(plist_data)


def query_plist(plist_path: str, query_path: str) -> Dict:
    """
    Query specific values from a property list file
    
    Args:
        plist_path: Path to the property list file
        query_path: Path to the desired value (e.g., "root.key1.key2")
        
    Returns:
        Dictionary with query results
    """
    logger.info(f"Querying plist: {plist_path} with path: {query_path}")
    
    # Parse the plist
    plist_data = parse_plist(plist_path)
    
    # Parse the query path
    path_parts = query_path.split('.')
    
    # Navigate the path
    current = plist_data
    for part in path_parts:
        if part == '':
            continue
        
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return {
                'plist_path': plist_path,
                'query_path': query_path,
                'found': False,
                'error': f"Path part '{part}' not found"
            }
    
    # Return the result
    return {
        'plist_path': plist_path,
        'query_path': query_path,
        'found': True,
        'result': current
    }


def find_plists(base_path: str) -> List[Dict]:
    """
    Find property list files in the specified directory
    
    Args:
        base_path: Base directory to search in
        
    Returns:
        List of dictionaries with plist information
    """
    logger.info(f"Searching for property lists in {base_path}")
    
    plists = []
    
    for root, _, files in os.walk(base_path):
        for filename in files:
            if filename.endswith('.plist'):
                file_path = os.path.join(root, filename)
                
                try:
                    if is_plist_file(file_path):
                        plist_info = {
                            'path': file_path,
                            'name': filename,
                            'size': os.path.getsize(file_path)
                        }
                        
                        # Try to determine if it's binary or XML
                        with open(file_path, 'rb') as f:
                            header = f.read(8)
                            is_binary = header.startswith(b'bplist')
                            plist_info['format'] = 'binary' if is_binary else 'xml'
                        
                        plists.append(plist_info)
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
    
    logger.info(f"Found {len(plists)} property list files")
    return plists


def analyze_plist_timestamps(plist_path: str) -> Dict:
    """
    Extract and analyze timestamps from a property list
    
    Args:
        plist_path: Path to the property list file
        
    Returns:
        Dictionary with timestamp analysis
    """
    logger.info(f"Analyzing timestamps in {plist_path}")
    
    # Parse the plist
    plist_data = parse_plist(plist_path)
    
    # Find all timestamps (recursive search)
    timestamps = _find_timestamps(plist_data)
    
    return {
        'plist_path': plist_path,
        'timestamp_count': len(timestamps),
        'timestamps': timestamps
    }


def _find_timestamps(data: Any, path: str = '') -> List[Dict]:
    """
    Recursively search for timestamps in plist data
    
    Args:
        data: Plist data to search
        path: Current path in the data structure
        
    Returns:
        List of dictionaries with timestamp information
    """
    results = []
    
    # Common timestamp key names
    timestamp_keys = [
        'timestamp', 'date', 'time', 'created', 'modified', 'accessed',
        'lastOpened', 'lastModified', 'creationDate', 'modificationDate',
        'lastAccessed', 'dateCreated', 'dateModified', 'dateAccessed',
        'startDate', 'endDate', 'lastUsed', 'firstUsed'
    ]
    
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            # Check if this key might contain a timestamp
            key_lower = key.lower()
            is_timestamp_key = any(ts_key in key_lower for ts_key in timestamp_keys)
            
            # Add value if it looks like a timestamp
            if is_timestamp_key and _is_timestamp_value(value):
                results.append({
                    'path': current_path,
                    'value': value,
                    'type': type(value).__name__
                })
            
            # Recurse into nested structures
            results.extend(_find_timestamps(value, current_path))
    
    elif isinstance(data, list):
        for i, item in enumerate(data):
            current_path = f"{path}[{i}]"
            results.extend(_find_timestamps(item, current_path))
    
    return results


def _is_timestamp_value(value: Any) -> bool:
    """
    Check if a value looks like a timestamp
    
    Args:
        value: Value to check
        
    Returns:
        True if the value looks like a timestamp
    """
    # Check for date objects
    if hasattr(value, 'year') and hasattr(value, 'month') and hasattr(value, 'day'):
        return True
    
    # Check for timestamp strings
    if isinstance(value, str):
        # ISO format date strings
        if len(value) > 8 and '-' in value and ':' in value:
            return True
        
        # RFC 822 format
        if len(value) > 10 and (',' in value or '+' in value) and ':' in value:
            return True
    
    # Check for numeric timestamps
    if isinstance(value, (int, float)):
        # Unix timestamps are typically 10-13 digits
        str_val = str(value)
        if len(str_val) >= 9 and len(str_val) <= 13:
            return True
    
    return False


def convert_plist(plist_path: str, output_format: str = 'xml') -> Dict:
    """
    Convert a property list between binary and XML formats
    
    Args:
        plist_path: Path to the property list file
        output_format: Output format ('xml' or 'binary')
        
    Returns:
        Dictionary with conversion results
    """
    logger.info(f"Converting plist {plist_path} to {output_format}")
    
    if output_format not in ['xml', 'binary']:
        raise ValueError("Output format must be 'xml' or 'binary'")
    
    # Parse the plist
    plist_data = parse_plist(plist_path)
    
    # Create output path
    base_path, filename = os.path.split(plist_path)
    name, _ = os.path.splitext(filename)
    output_path = os.path.join(base_path, f"{name}.{'plist' if output_format == 'xml' else 'bplist'}")
    
    # Write the converted plist
    try:
        with open(output_path, 'wb') as f:
            if output_format == 'xml':
                plistlib.dump(plist_data, f, fmt=plistlib.FMT_XML)
            else:
                plistlib.dump(plist_data, f, fmt=plistlib.FMT_BINARY)
        
        return {
            'source_path': plist_path,
            'output_path': output_path,
            'output_format': output_format,
            'success': True
        }
    except Exception as e:
        logger.error(f"Error converting plist {plist_path}: {e}")
        raise
