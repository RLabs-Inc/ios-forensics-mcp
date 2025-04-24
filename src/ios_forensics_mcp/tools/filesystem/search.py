# tools/filesystem/search.py - File search utilities

import os
import re
from typing import Dict, List, Any, Optional, Union

def search_files(base_path: str, pattern: str, search_type: str = 'filename') -> Dict[str, Any]:
    """
    Search for files matching pattern
    
    Args:
        base_path: Base directory to search in
        pattern: Search pattern
        search_type: Type of search ('filename', 'content', 'regex')
        
    Returns:
        Dictionary with search results
    """
    if not os.path.exists(base_path):
        raise FileNotFoundError(f"Base path does not exist: {base_path}")
    
    if not os.path.isdir(base_path):
        raise NotADirectoryError(f"Base path is not a directory: {base_path}")
    
    # Validate search type
    valid_search_types = ['filename', 'content', 'regex']
    if search_type not in valid_search_types:
        raise ValueError(f"Invalid search type: {search_type}. Must be one of {valid_search_types}")
    
    result = {
        'base_path': base_path,
        'pattern': pattern,
        'search_type': search_type,
        'matches': [],
        'match_count': 0
    }
    
    # Different search implementations based on search type
    if search_type == 'filename':
        result = _search_by_filename(base_path, pattern, result)
    elif search_type == 'content':
        result = _search_by_content(base_path, pattern, result)
    elif search_type == 'regex':
        try:
            regex = re.compile(pattern)
            result = _search_by_regex(base_path, regex, result)
        except re.error as e:
            raise ValueError(f"Invalid regular expression: {pattern}. Error: {str(e)}")
    
    return result

def _search_by_filename(base_path: str, pattern: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Search for files by name
    
    Args:
        base_path: Base directory to search in
        pattern: Filename pattern (case-insensitive substring match)
        result: Result dictionary to update
        
    Returns:
        Updated result dictionary
    """
    pattern = pattern.lower()
    matches = []
    
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if pattern in file.lower():
                file_path = os.path.join(root, file)
                
                try:
                    # Get basic file stats
                    stat_info = os.stat(file_path)
                    
                    matches.append({
                        'path': file_path,
                        'name': file,
                        'size': stat_info.st_size,
                        'modified': stat_info.st_mtime
                    })
                except (PermissionError, FileNotFoundError) as e:
                    # Handle errors for individual files
                    matches.append({
                        'path': file_path,
                        'name': file,
                        'error': str(e)
                    })
    
    # Sort matches by name
    matches.sort(key=lambda x: x.get('name', ''))
    
    result['matches'] = matches
    result['match_count'] = len(matches)
    
    return result

def _search_by_content(base_path: str, pattern: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Search for files containing pattern in their content
    
    Args:
        base_path: Base directory to search in
        pattern: Content pattern (case-insensitive substring match)
        result: Result dictionary to update
        
    Returns:
        Updated result dictionary
    """
    matches = []
    pattern = pattern.encode() if isinstance(pattern, str) else pattern
    
    for root, dirs, files in os.walk(base_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            try:
                # Skip very large files (> 10MB) for performance
                file_size = os.path.getsize(file_path)
                if file_size > 10_000_000:
                    continue
                
                # Read file and search for pattern
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                if pattern.lower() in content.lower():
                    # Find line numbers and context for matches
                    line_matches = []
                    text_content = None
                    
                    try:
                        # Try to decode content as text for line context
                        text_content = content.decode('utf-8', errors='replace')
                        lines = text_content.split('\n')
                        
                        # Find line numbers containing pattern
                        pattern_str = pattern.decode('utf-8', errors='replace').lower()
                        for i, line in enumerate(lines):
                            if pattern_str in line.lower():
                                # Get context (line before, match line, line after)
                                context = {
                                    'line_number': i + 1,
                                    'line': line.strip()
                                }
                                
                                if i > 0:
                                    context['previous_line'] = lines[i-1].strip()
                                if i < len(lines) - 1:
                                    context['next_line'] = lines[i+1].strip()
                                
                                line_matches.append(context)
                                
                                # Limit to 10 matches per file
                                if len(line_matches) >= 10:
                                    break
                    except Exception:
                        # If text decoding fails, just record that it's a binary match
                        line_matches = [{'binary_match': True}]
                    
                    matches.append({
                        'path': file_path,
                        'name': file,
                        'size': file_size,
                        'modified': os.path.getmtime(file_path),
                        'line_matches': line_matches,
                        'match_count': len(line_matches),
                        'is_binary': text_content is None
                    })
            except (PermissionError, FileNotFoundError, IOError) as e:
                # Skip files that can't be read
                continue
    
    # Sort matches by name
    matches.sort(key=lambda x: x.get('name', ''))
    
    result['matches'] = matches
    result['match_count'] = len(matches)
    
    return result

def _search_by_regex(base_path: str, regex: re.Pattern, result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Search for files matching regex pattern
    
    Args:
        base_path: Base directory to search in
        regex: Compiled regular expression pattern
        result: Result dictionary to update
        
    Returns:
        Updated result dictionary
    """
    matches = []
    
    # First search filenames
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if regex.search(file):
                file_path = os.path.join(root, file)
                
                try:
                    # Get basic file stats
                    stat_info = os.stat(file_path)
                    
                    matches.append({
                        'path': file_path,
                        'name': file,
                        'size': stat_info.st_size,
                        'modified': stat_info.st_mtime,
                        'match_type': 'filename'
                    })
                except (PermissionError, FileNotFoundError) as e:
                    # Handle errors for individual files
                    matches.append({
                        'path': file_path,
                        'name': file,
                        'error': str(e),
                        'match_type': 'filename'
                    })
    
    # Then search file contents
    for root, dirs, files in os.walk(base_path):
        for file in files:
            # Skip files we already matched by name
            file_path = os.path.join(root, file)
            if any(m['path'] == file_path for m in matches):
                continue
            
            try:
                # Skip very large files (> 10MB) for performance
                file_size = os.path.getsize(file_path)
                if file_size > 10_000_000:
                    continue
                
                # Read file and search for pattern
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                try:
                    # Try to decode content as text for regex search
                    text_content = content.decode('utf-8', errors='replace')
                    
                    # Find all regex matches
                    content_matches = list(regex.finditer(text_content))
                    
                    if content_matches:
                        # Find line numbers and context for matches
                        line_matches = []
                        lines = text_content.split('\n')
                        
                        # Create a map from character position to line number
                        line_offsets = [0]
                        pos = 0
                        for line in lines:
                            pos += len(line) + 1  # +1 for the newline
                            line_offsets.append(pos)
                        
                        # For each match, find the line numbers
                        for match in content_matches:
                            start_pos = match.start()
                            
                            # Find the line containing this position
                            line_index = 0
                            for i, offset in enumerate(line_offsets):
                                if offset > start_pos:
                                    line_index = i - 1
                                    break
                            
                            if line_index < len(lines):
                                context = {
                                    'line_number': line_index + 1,
                                    'line': lines[line_index].strip(),
                                    'match': match.group()
                                }
                                
                                if line_index > 0:
                                    context['previous_line'] = lines[line_index-1].strip()
                                if line_index < len(lines) - 1:
                                    context['next_line'] = lines[line_index+1].strip()
                                
                                line_matches.append(context)
                                
                                # Limit to 10 matches per file
                                if len(line_matches) >= 10:
                                    break
                        
                        matches.append({
                            'path': file_path,
                            'name': file,
                            'size': file_size,
                            'modified': os.path.getmtime(file_path),
                            'line_matches': line_matches,
                            'match_count': len(line_matches),
                            'match_type': 'content',
                            'is_binary': False
                        })
                except UnicodeDecodeError:
                    # If text decoding fails, check for binary regex match
                    # This is much more limited, but can find some patterns
                    try:
                        binary_matches = list(regex.finditer(str(content)))
                        if binary_matches:
                            matches.append({
                                'path': file_path,
                                'name': file,
                                'size': file_size,
                                'modified': os.path.getmtime(file_path),
                                'match_count': len(binary_matches),
                                'match_type': 'content',
                                'is_binary': True
                            })
                    except Exception:
                        pass
            except (PermissionError, FileNotFoundError, IOError) as e:
                # Skip files that can't be read
                continue
    
    # Sort matches by name
    matches.sort(key=lambda x: x.get('name', ''))
    
    result['matches'] = matches
    result['match_count'] = len(matches)
    
    return result