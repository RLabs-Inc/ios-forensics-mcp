# utils/path_utils.py - Path validation and manipulation utilities

import os
import re
from typing import List, Optional, Tuple

def normalize_path(path: str) -> str:
    """
    Normalize a path by converting backslashes to forward slashes
    and removing redundant separators
    
    Args:
        path: The path to normalize
        
    Returns:
        Normalized path string
    """
    # Replace backslashes with forward slashes
    normalized = path.replace('\\', '/')
    
    # Remove duplicate slashes
    normalized = re.sub(r'/+', '/', normalized)
    
    # Remove trailing slash
    if normalized != '/' and normalized.endswith('/'):
        normalized = normalized[:-1]
        
    return normalized


def get_absolute_path(base_path: str, relative_path: str) -> str:
    """
    Convert a relative path to an absolute path within the base directory
    
    Args:
        base_path: The base directory (iOS root)
        relative_path: The path relative to the base directory
        
    Returns:
        Absolute path
    """
    # Handle root path
    if relative_path == '/' or relative_path == '':
        return base_path
    
    # Strip leading slash if present
    if relative_path.startswith('/'):
        relative_path = relative_path[1:]
    
    # Join paths and normalize
    full_path = os.path.normpath(os.path.join(base_path, relative_path))
    
    return full_path


def is_path_valid(path: str, base_path: str) -> bool:
    """
    Check if a path is valid and within the allowed base directory
    
    Args:
        path: The path to validate
        base_path: The base directory (iOS root)
        
    Returns:
        True if the path is valid, False otherwise
    """
    # Normalize paths for comparison
    norm_path = os.path.normpath(path)
    norm_base = os.path.normpath(base_path)
    
    # Check if path exists
    if not os.path.exists(norm_path):
        return False
    
    # Check if path is within base directory
    common_path = os.path.commonpath([norm_path, norm_base])
    return common_path == norm_base


def is_file_readable(path: str) -> bool:
    """
    Check if a file exists and is readable
    
    Args:
        path: The file path to check
        
    Returns:
        True if the file exists and is readable, False otherwise
    """
    return os.path.isfile(path) and os.access(path, os.R_OK)


def get_file_metadata(path: str) -> dict:
    """
    Get metadata for a file
    
    Args:
        path: The file path
        
    Returns:
        Dictionary containing file metadata
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path does not exist: {path}")
    
    stat_info = os.stat(path)
    
    metadata = {
        'name': os.path.basename(path),
        'path': path,
        'size': stat_info.st_size,
        'is_directory': os.path.isdir(path),
        'created': stat_info.st_ctime,
        'modified': stat_info.st_mtime,
        'accessed': stat_info.st_atime,
        'permissions': oct(stat_info.st_mode)[-3:],  # Last 3 digits of octal permissions
    }
    
    return metadata


def find_files_by_extension(base_path: str, extensions: List[str], recursive: bool = True) -> List[str]:
    """
    Find files with specific extensions in a directory
    
    Args:
        base_path: The base directory to search in
        extensions: List of file extensions to find (without dot)
        recursive: Whether to search recursively
        
    Returns:
        List of matching file paths
    """
    if not os.path.isdir(base_path):
        raise ValueError(f"Base path is not a directory: {base_path}")
    
    # Normalize extensions by adding dot if needed
    normalized_extensions = []
    for ext in extensions:
        if not ext.startswith('.'):
            ext = '.' + ext
        normalized_extensions.append(ext.lower())
    
    matching_files = []
    
    if recursive:
        for root, _, files in os.walk(base_path):
            for filename in files:
                _, ext = os.path.splitext(filename.lower())
                if ext in normalized_extensions:
                    matching_files.append(os.path.join(root, filename))
    else:
        for item in os.listdir(base_path):
            item_path = os.path.join(base_path, item)
            if os.path.isfile(item_path):
                _, ext = os.path.splitext(item.lower())
                if ext in normalized_extensions:
                    matching_files.append(item_path)
    
    return matching_files


def get_relative_path(full_path: str, base_path: str) -> str:
    """
    Convert an absolute path to a path relative to the base directory
    
    Args:
        full_path: The absolute path
        base_path: The base directory (iOS root)
        
    Returns:
        Path relative to the base directory
    """
    # Normalize paths for comparison
    norm_path = os.path.normpath(full_path)
    norm_base = os.path.normpath(base_path)
    
    # Check if path is within base directory
    if not norm_path.startswith(norm_base):
        raise ValueError(f"Path {full_path} is not within base directory {base_path}")
    
    # Get relative path
    rel_path = os.path.relpath(norm_path, norm_base)
    
    # Convert to forward slashes for consistency
    rel_path = rel_path.replace('\\', '/')
    
    # Add leading slash
    if not rel_path.startswith('/'):
        rel_path = '/' + rel_path
    
    return rel_path


def find_common_ios_paths() -> dict:
    """
    Return a dictionary of common iOS paths and their descriptions
    
    Returns:
        Dictionary mapping iOS paths to descriptions
    """
    return {
        # System
        '/private/var/mobile': 'User home directory for mobile user',
        '/private/var/root': 'Root user home directory',
        '/private/var/containers': 'App containers and data',
        '/private/var/mobile/Library': 'User library containing most user data',
        
        # Messaging
        '/private/var/mobile/Library/SMS': 'SMS and iMessage database directory',
        '/private/var/mobile/Library/SMS/sms.db': 'Main SMS/iMessage database',
        
        # Calls
        '/private/var/mobile/Library/CallHistory': 'Call history directory',
        '/private/var/mobile/Library/CallHistory/call_history.db': 'Call history database',
        
        # Contacts
        '/private/var/mobile/Library/AddressBook': 'Address book directory',
        '/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb': 'Main contacts database',
        
        # Safari
        '/private/var/mobile/Library/Safari': 'Safari browser data',
        '/private/var/mobile/Library/Safari/History.db': 'Safari browsing history',
        '/private/var/mobile/Library/Safari/Bookmarks.db': 'Safari bookmarks',
        
        # Photos
        '/private/var/mobile/Media/DCIM': 'Camera photos directory',
        '/private/var/mobile/Media/PhotoData': 'Photo library data',
        '/private/var/mobile/Media/PhotoData/Photos.sqlite': 'Photos database',
        
        # Notes
        '/private/var/mobile/Library/Notes': 'Notes directory',
        '/private/var/mobile/Containers/Shared/AppGroup/*/NoteStore.sqlite': 'Notes database',
        
        # Calendar
        '/private/var/mobile/Library/Calendar': 'Calendar directory',
        '/private/var/mobile/Library/Calendar/Calendar.sqlitedb': 'Calendar database',
        
        # Location
        '/private/var/mobile/Library/Caches/com.apple.routined': 'Location history',
        '/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite': 'Significant locations database',
        
        # Health
        '/private/var/mobile/Library/Health': 'Health data directory',
        '/private/var/mobile/Library/Health/healthdb.sqlite': 'Health database',
        
        # Applications
        '/private/var/containers/Bundle/Application': 'Installed app bundles',
        '/private/var/mobile/Containers/Data/Application': 'App data containers',
        '/private/var/mobile/Containers/Shared/AppGroup': 'Shared app containers',
        
        # Keychain
        '/private/var/Keychains': 'Keychain databases',
        
        # System Configuration
        '/private/var/mobile/Library/Preferences': 'System and app preferences',
        '/private/var/mobile/Library/ConfigurationProfiles': 'Installed profiles',
    }


def is_common_database_path(path: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a path corresponds to a known iOS database
    
    Args:
        path: Path to check
        
    Returns:
        Tuple of (is_known_db, description)
    """
    common_dbs = {
        'sms.db': 'SMS and iMessage database',
        'call_history.db': 'Call history database',
        'AddressBook.sqlitedb': 'Contacts database',
        'History.db': 'Safari browsing history',
        'Photos.sqlite': 'Photos database',
        'NoteStore.sqlite': 'Notes database',
        'Calendar.sqlitedb': 'Calendar database',
        'Cache.sqlite': 'Location cache database',
        'healthdb.sqlite': 'Health data database',
        'Bookmarks.db': 'Safari bookmarks database',
        'notes.sqlite': 'Notes database (older iOS)',
        'consolidated.db': 'Location database (older iOS)',
        'voicemail.db': 'Voicemail database',
        'MailCaches': 'Mail cache database',
    }
    
    filename = os.path.basename(path)
    
    if filename in common_dbs:
        return True, common_dbs[filename]
    
    return False, None
