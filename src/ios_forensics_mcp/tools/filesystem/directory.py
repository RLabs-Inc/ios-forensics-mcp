# tools/filesystem/directory.py - Directory listing utilities

import os
import stat
from typing import Dict, List, Optional, Any, Union

def list_directory(path: str, recursive: bool = False, show_hidden: bool = False) -> Dict[str, Any]:
    """
    List contents of a directory with detailed metadata
    
    Args:
        path: Path to the directory
        recursive: Whether to list directories recursively
        show_hidden: Whether to show hidden files
        
    Returns:
        Dictionary with directory contents and metadata
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")
    
    if not os.path.isdir(path):
        raise NotADirectoryError(f"Path is not a directory: {path}")
    
    result = {
        'path': path,
        'name': os.path.basename(path),
        'is_directory': True,
        'children': [],
        'count': {
            'files': 0,
            'directories': 0,
            'total': 0
        }
    }
    
    # List directory contents
    try:
        items = os.listdir(path)
        
        # Filter hidden files if not showing them
        if not show_hidden:
            items = [item for item in items if not item.startswith('.')]
        
        # Process each item
        for item in items:
            item_path = os.path.join(path, item)
            
            try:
                # Get basic file stats
                stat_info = os.stat(item_path)
                is_dir = os.path.isdir(item_path)
                
                # Update counts
                if is_dir:
                    result['count']['directories'] += 1
                else:
                    result['count']['files'] += 1
                
                result['count']['total'] += 1
                
                # Create item info
                item_info = {
                    'name': item,
                    'path': item_path,
                    'is_directory': is_dir,
                    'size': stat_info.st_size,
                    'created': stat_info.st_ctime,
                    'modified': stat_info.st_mtime,
                    'accessed': stat_info.st_atime,
                    'permissions': stat.filemode(stat_info.st_mode)
                }
                
                # If recursive and item is a directory, list its contents
                if recursive and is_dir:
                    try:
                        item_info['children'] = list_directory(item_path, recursive, show_hidden)
                    except (PermissionError, FileNotFoundError) as e:
                        item_info['error'] = str(e)
                
                result['children'].append(item_info)
                
            except (PermissionError, FileNotFoundError) as e:
                # Handle errors for individual items
                result['children'].append({
                    'name': item,
                    'path': item_path,
                    'error': str(e)
                })
    
    except PermissionError as e:
        raise PermissionError(f"Permission denied accessing directory: {path}. {str(e)}")
    
    # Sort children by name
    result['children'].sort(key=lambda x: x['name'])
    
    return result