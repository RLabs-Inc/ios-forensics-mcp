# tools/filesystem/file_reader.py - File reading utilities

import os
import chardet
from typing import Dict, Optional, Any, Union, BinaryIO

def read_file(path: str, encoding: str = 'auto', offset: int = 0, length: Optional[int] = None) -> Dict[str, Any]:
    """
    Read and return file contents with encoding detection
    
    Args:
        path: Path to the file
        encoding: File encoding ('auto', 'utf-8', 'binary', etc.)
        offset: Starting byte offset
        length: Number of bytes to read (None for entire file)
        
    Returns:
        Dictionary with file contents and metadata
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    
    if not os.path.isfile(path):
        raise IsADirectoryError(f"Path is a directory, not a file: {path}")
    
    file_size = os.path.getsize(path)
    
    # Validate offset and length
    if offset < 0:
        raise ValueError("Offset must be non-negative")
    
    if offset > file_size:
        raise ValueError(f"Offset {offset} exceeds file size {file_size}")
    
    # Calculate actual length to read
    if length is None:
        length = file_size - offset
    elif length < 0:
        raise ValueError("Length must be non-negative")
    elif offset + length > file_size:
        length = file_size - offset
    
    # Prepare result dictionary
    result = {
        'path': path,
        'name': os.path.basename(path),
        'size': file_size,
        'offset': offset,
        'length': length,
        'encoding': encoding
    }
    
    # Read file content
    try:
        with open(path, 'rb') as f:
            f.seek(offset)
            data = f.read(length)
        
        # Handle encoding
        if encoding.lower() == 'auto':
            # Try to detect encoding
            detection = chardet.detect(data)
            detected_encoding = detection['encoding'] if detection['encoding'] else 'utf-8'
            confidence = detection['confidence']
            
            result['detected_encoding'] = detected_encoding
            result['encoding_confidence'] = confidence
            
            try:
                # Try to decode with detected encoding
                content = data.decode(detected_encoding)
                result['content'] = content
                result['is_binary'] = False
                result['encoding'] = detected_encoding
            except UnicodeDecodeError:
                # If decode fails, treat as binary
                result['content'] = data.hex()
                result['is_binary'] = True
                result['encoding'] = 'binary'
        
        elif encoding.lower() == 'binary':
            # Return binary data as hex
            result['content'] = data.hex()
            result['is_binary'] = True
        
        else:
            # Try specified encoding
            try:
                content = data.decode(encoding)
                result['content'] = content
                result['is_binary'] = False
            except UnicodeDecodeError:
                # If decode fails, treat as binary
                result['content'] = data.hex()
                result['is_binary'] = True
                result['encoding'] = 'binary'
    
    except (PermissionError, IOError) as e:
        raise IOError(f"Error reading file {path}: {str(e)}")
    
    return result