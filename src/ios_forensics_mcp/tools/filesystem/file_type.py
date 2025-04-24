# tools/filesystem/file_type.py - File type identification utilities

import os
import mimetypes
from typing import Dict, Any

# Initialize mimetypes
mimetypes.init()

# Common file signatures (magic numbers) and their descriptions
FILE_SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': 'PNG image',
    b'\xff\xd8\xff': 'JPEG image',
    b'GIF87a': 'GIF image',
    b'GIF89a': 'GIF image',
    b'BM': 'BMP image',
    b'%PDF': 'PDF document',
    b'PK\x03\x04': 'ZIP archive',
    b'Rar!\x1a\x07': 'RAR archive',
    b'7z\xbc\xaf\x27\x1c': '7-Zip archive',
    b'\x1f\x8b\x08': 'GZIP archive',
    b'SQLite format': 'SQLite database',
    b'bplist00': 'Binary property list',
    b'<?xml': 'XML document',
    b'{\r\n': 'JSON document',
    b'{\n': 'JSON document',
    b'#!/': 'Script',
    b'#!': 'Script',
    b'\xca\xfe\xba\xbe': 'Java class file',
    b'\xfe\xed\xfa\xce': 'Mach-O binary (32-bit)',
    b'\xce\xfa\xed\xfe': 'Mach-O binary (32-bit)',
    b'\xfe\xed\xfa\xcf': 'Mach-O binary (64-bit)',
    b'\xcf\xfa\xed\xfe': 'Mach-O binary (64-bit)',
}

def identify_file_type(path: str) -> Dict[str, Any]:
    """
    Identify file type based on signature/magic bytes and extension
    
    Args:
        path: Path to the file
        
    Returns:
        Dictionary with file type information
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    
    if not os.path.isfile(path):
        raise IsADirectoryError(f"Path is a directory, not a file: {path}")
    
    # Get file size
    file_size = os.path.getsize(path)
    
    # Initialize result
    result = {
        'path': path,
        'name': os.path.basename(path),
        'size': file_size,
        'extension': os.path.splitext(path)[1].lower(),
        'mime_type': None,
        'description': None,
        'signature_match': None,
        'is_text': False,
        'is_binary': True,
        'is_empty': file_size == 0
    }
    
    # Get MIME type based on extension
    mime_type, _ = mimetypes.guess_type(path)
    result['mime_type'] = mime_type
    
    # If file is empty, no need for further analysis
    if file_size == 0:
        result['description'] = 'Empty file'
        return result
    
    # Read the first 4KB for signature detection
    with open(path, 'rb') as f:
        header = f.read(4096)
    
    # Check for known signatures
    for signature, description in FILE_SIGNATURES.items():
        if header.startswith(signature):
            result['signature_match'] = signature.hex()
            result['description'] = description
            break
    
    # If no signature match, try to determine if it's text or binary
    if not result['description']:
        # Simple heuristic to determine if text or binary
        is_text = True
        for byte in header:
            # Check if byte is outside printable ASCII range and not a common control character
            if byte < 8 or (byte > 13 and byte < 32) or byte > 126:
                is_text = False
                break
        
        result['is_text'] = is_text
        result['is_binary'] = not is_text
        
        if is_text:
            result['description'] = 'Text file'
        else:
            result['description'] = 'Binary file'
    
    # SQLite database detection (more specific than just the header check)
    if result['extension'] in ['.db', '.sqlite', '.sqlite3', '.sqlitedb']:
        if header.startswith(b'SQLite format'):
            result['description'] = 'SQLite database'
        elif b'SQLite format' in header:
            result['description'] = 'SQLite database'
    
    # Property list detection
    if result['extension'] == '.plist':
        if header.startswith(b'bplist00'):
            result['description'] = 'Binary property list'
        elif header.startswith(b'<?xml') and b'<!DOCTYPE plist' in header:
            result['description'] = 'XML property list'
        elif b'<plist' in header:
            result['description'] = 'XML property list'
    
    return result