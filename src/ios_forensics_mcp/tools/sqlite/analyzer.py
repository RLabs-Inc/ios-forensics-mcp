# tools/sqlite/analyzer.py - SQLite database analysis tools

import os
import sqlite3
import json
import logging
from typing import Dict, List, Optional, Any, Tuple, Union

# Set up logging
logger = logging.getLogger(__name__)

# Import utilities
from utils.path_utils import find_files_by_extension, is_common_database_path


def is_sqlite_database(file_path: str) -> bool:
    """
    Check if a file is a valid SQLite database
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file is a valid SQLite database, False otherwise
    """
    if not os.path.isfile(file_path):
        return False
    
    # Check for SQLite magic header (first 16 bytes)
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
        
        # Check for SQLite format 3 magic string
        return header[:16] == b'SQLite format 3\x00'
    except Exception as e:
        logger.error(f"Error checking SQLite header for {file_path}: {e}")
        return False


def find_databases(base_path: str) -> List[Dict]:
    """
    Find SQLite databases in the specified directory
    
    Args:
        base_path: Base directory to search in
        
    Returns:
        List of dictionaries with database information
    """
    logger.info(f"Searching for SQLite databases in {base_path}")
    
    # Find files with common SQLite extensions
    candidates = find_files_by_extension(
        base_path,
        ['db', 'sqlite', 'sqlitedb', 'sqlite3', 'db3'],
        recursive=True
    )
    
    databases = []
    
    for candidate in candidates:
        try:
            if is_sqlite_database(candidate):
                # Check if this is a known iOS database
                is_known, description = is_common_database_path(candidate)
                
                # Get database info
                db_info = {
                    'path': candidate,
                    'name': os.path.basename(candidate),
                    'size': os.path.getsize(candidate),
                    'is_known': is_known,
                }
                
                if is_known and description:
                    db_info['description'] = description
                
                # Get basic schema info
                try:
                    conn = sqlite3.connect(candidate)
                    cursor = conn.cursor()
                    
                    # Get table count
                    cursor.execute("SELECT COUNT(name) FROM sqlite_master WHERE type='table'")
                    table_count = cursor.fetchone()[0]
                    db_info['table_count'] = table_count
                    
                    # Get table list
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cursor.fetchall()]
                    db_info['tables'] = tables
                    
                    conn.close()
                except Exception as e:
                    logger.warning(f"Could not read schema for {candidate}: {e}")
                    db_info['error'] = str(e)
                
                databases.append(db_info)
        except Exception as e:
            logger.error(f"Error checking {candidate}: {e}")
    
    logger.info(f"Found {len(databases)} SQLite databases")
    return databases


def analyze_schema(db_path: str) -> Dict:
    """
    Analyze the schema of a SQLite database
    
    Args:
        db_path: Path to the SQLite database
        
    Returns:
        Dictionary with database schema information
    """
    logger.info(f"Analyzing schema for {db_path}")
    
    if not is_sqlite_database(db_path):
        raise ValueError(f"Not a valid SQLite database: {db_path}")
    
    try:
        # Create a temporary copy of the database for forensic integrity
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        temp_db_path = os.path.join(temp_dir, os.path.basename(db_path))
        
        # Copy the database file
        shutil.copy2(db_path, temp_db_path)
        
        # Check for and handle WAL and SHM files
        wal_path = f"{db_path}-wal"
        shm_path = f"{db_path}-shm"
        
        if os.path.exists(wal_path):
            temp_wal_path = f"{temp_db_path}-wal"
            shutil.copy2(wal_path, temp_wal_path)
            logger.info(f"Copied WAL file to temporary location: {temp_wal_path}")
        
        if os.path.exists(shm_path):
            temp_shm_path = f"{temp_db_path}-shm"
            shutil.copy2(shm_path, temp_shm_path)
            logger.info(f"Copied SHM file to temporary location: {temp_shm_path}")
        
        # Open the temporary copy with SQLITE_OPEN_READONLY flag to prevent modification
        # Use URI format to specify flags
        uri = f"file:{temp_db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        
        # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
        conn.execute("PRAGMA journal_mode=OFF")
        
        # Disable WAL mode to prevent modification of the WAL file
        conn.execute("PRAGMA locking_mode=NORMAL")
        
        cursor = conn.cursor()
        
        # Get database metadata
        is_known, description = is_common_database_path(db_path)
        
        schema_info = {
            'path': db_path,
            'name': os.path.basename(db_path),
            'is_known': is_known,
            'tables': [],
            'indexes': [],
            'triggers': [],
            'has_wal': os.path.exists(wal_path),
            'has_shm': os.path.exists(shm_path),
            'used_temp_copy': True
        }
        
        if is_known and description:
            schema_info['description'] = description
        
        # Get tables
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        for name, sql in cursor.fetchall():
            table_info = {'name': name, 'sql': sql, 'columns': []}
            
            # Get columns
            try:
                cursor.execute(f"PRAGMA table_info({name})")
                for cid, column_name, column_type, not_null, default_value, pk in cursor.fetchall():
                    column_info = {
                        'cid': cid,
                        'name': column_name,
                        'type': column_type,
                        'not_null': bool(not_null),
                        'default_value': default_value,
                        'primary_key': bool(pk)
                    }
                    table_info['columns'].append(column_info)
            except Exception as e:
                logger.warning(f"Could not get column info for table {name}: {e}")
                table_info['error'] = f"Could not get column info: {str(e)}"
            
            # Get record count
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {name}")
                table_info['record_count'] = cursor.fetchone()[0]
            except Exception as e:
                logger.warning(f"Could not get record count for table {name}: {e}")
                table_info['record_count'] = "Error"
            
            schema_info['tables'].append(table_info)
        
        # Get indexes
        cursor.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'")
        for name, table_name, sql in cursor.fetchall():
            if name.startswith('sqlite_'):  # Skip internal indexes
                continue
                
            index_info = {
                'name': name,
                'table': table_name,
                'sql': sql
            }
            schema_info['indexes'].append(index_info)
        
        # Get triggers
        cursor.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger'")
        for name, table_name, sql in cursor.fetchall():
            trigger_info = {
                'name': name,
                'table': table_name,
                'sql': sql
            }
            schema_info['triggers'].append(trigger_info)
        
        cursor.close()
        conn.close()
        
        # Clean up temporary files
        try:
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            if os.path.exists(f"{temp_db_path}-shm"):
                os.remove(f"{temp_db_path}-shm")
            os.rmdir(temp_dir)
        except Exception as e:
            logger.warning(f"Error cleaning up temporary files: {e}")
        
        return schema_info
    
    except Exception as e:
        logger.error(f"Error analyzing schema for {db_path}: {e}")
        raise


def execute_query(db_path: str, query: str, params: Optional[Dict[str, Any]] = None) -> Dict:
    """
    Execute a SQL query against a SQLite database
    
    Args:
        db_path: Path to the SQLite database
        query: SQL query to execute
        params: Query parameters (optional)
        
    Returns:
        Dictionary with query results
    """
    logger.info(f"Executing query on {db_path}")
    
    if not is_sqlite_database(db_path):
        raise ValueError(f"Not a valid SQLite database: {db_path}")
    
    # Validate query to prevent SQL injection
    query = query.strip()
    if not query:
        raise ValueError("Empty query")
    
    # Disallow multiple statements
    if ";" in query[:-1]:  # Allow trailing semicolon
        raise ValueError("Multiple SQL statements are not allowed")
    
    # Disallow potentially destructive operations
    forbidden_keywords = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "ATTACH", "DETACH", "PRAGMA"]
    for keyword in forbidden_keywords:
        if keyword in query.upper().split():
            raise ValueError(f"Operation not allowed: {keyword}")
    
    try:
        # Create a temporary copy of the database for forensic integrity
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp()
        temp_db_path = os.path.join(temp_dir, os.path.basename(db_path))
        
        # Copy the database file
        shutil.copy2(db_path, temp_db_path)
        
        # Check for and handle WAL and SHM files
        wal_path = f"{db_path}-wal"
        shm_path = f"{db_path}-shm"
        
        if os.path.exists(wal_path):
            temp_wal_path = f"{temp_db_path}-wal"
            shutil.copy2(wal_path, temp_wal_path)
            logger.info(f"Copied WAL file to temporary location: {temp_wal_path}")
        
        if os.path.exists(shm_path):
            temp_shm_path = f"{temp_db_path}-shm"
            shutil.copy2(shm_path, temp_shm_path)
            logger.info(f"Copied SHM file to temporary location: {temp_shm_path}")
        
        # Open the temporary copy with SQLITE_OPEN_READONLY flag to prevent modification
        # Use URI format to specify flags
        uri = f"file:{temp_db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row  # Return results as dictionaries
        
        # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
        conn.execute("PRAGMA journal_mode=OFF")
        
        # Disable WAL mode to prevent modification of the WAL file
        conn.execute("PRAGMA locking_mode=NORMAL")
        
        cursor = conn.cursor()
        
        # Execute the query
        start_time = os.times()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        # Get column names
        column_names = [description[0] for description in cursor.description] if cursor.description else []
        
        # Fetch results (limit to 1000 rows for performance)
        MAX_ROWS = 1000
        rows = cursor.fetchmany(MAX_ROWS)
        row_count = len(rows)
        has_more = row_count == MAX_ROWS
        
        # Convert rows to dictionaries
        results = []
        for row in rows:
            results.append({column_names[i]: row[i] for i in range(len(column_names))})
        
        # Get execution time
        end_time = os.times()
        execution_time = (end_time.user - start_time.user) + (end_time.system - start_time.system)
        
        cursor.close()
        conn.close()
        
        # Clean up temporary files
        try:
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            if os.path.exists(f"{temp_db_path}-shm"):
                os.remove(f"{temp_db_path}-shm")
            os.rmdir(temp_dir)
        except Exception as e:
            logger.warning(f"Error cleaning up temporary files: {e}")
        
        return {
            'column_names': column_names,
            'rows': results,
            'row_count': row_count,
            'has_more': has_more,
            'execution_time': execution_time,
            'query': query,
            'used_temp_copy': True
        }
    
    except Exception as e:
        logger.error(f"Error executing query on {db_path}: {e}")
        raise


def get_table_data(db_path: str, table_name: str, limit: int = 100, offset: int = 0) -> Dict:
    """
    Get data from a table in a SQLite database
    
    Args:
        db_path: Path to the SQLite database
        table_name: Name of the table
        limit: Maximum number of rows to return
        offset: Offset for pagination
        
    Returns:
        Dictionary with table data
    """
    # Validate table name to prevent SQL injection
    table_name = table_name.strip('\'"`[]')
    
    # Build and execute query
    query = f"SELECT * FROM '{table_name}' LIMIT ? OFFSET ?"
    params = {'limit': limit, 'offset': offset}
    
    return execute_query(db_path, query, params)


def recover_deleted_records(db_path: str, table_name: Optional[str] = None) -> Dict:
    """
    Attempt to recover deleted records from a SQLite database
    
    Args:
        db_path: Path to the SQLite database
        table_name: Optional table name to focus recovery
        
    Returns:
        Dictionary with recovered records
    """
    logger.info(f"Attempting to recover deleted records from {db_path}")
    
    if not is_sqlite_database(db_path):
        raise ValueError(f"Not a valid SQLite database: {db_path}")
    
    # This is a simplified implementation
    # A complete implementation would analyze free pages and unallocated space
    
    try:
        # Open the database file in binary mode to scan for record fragments
        with open(db_path, 'rb') as f:
            content = f.read()
        
        recovered_data = {
            'path': db_path,
            'name': os.path.basename(db_path),
            'recovered': []
        }
        
        # Connect to get schema information
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get tables to analyze
        tables_to_analyze = []
        if table_name:
            # Validate table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            if cursor.fetchone():
                tables_to_analyze.append(table_name)
            else:
                raise ValueError(f"Table does not exist: {table_name}")
        else:
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables_to_analyze = [row[0] for row in cursor.fetchall()]
        
        # Analyze each table
        for table in tables_to_analyze:
            table_data = {
                'table': table,
                'possible_records': []
            }
            
            # Get column names
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [row[1] for row in cursor.fetchall()]
            table_data['columns'] = columns
            
            # Simple heuristic recovery based on known patterns
            # This is a placeholder for a more sophisticated recovery algorithm
            # In a real implementation, this would analyze free pages and unallocated space
            
            # For now, just report that recovery requires a more sophisticated approach
            table_data['message'] = "Full recovery of deleted records requires advanced forensic techniques that analyze database file structure directly. Consider using specialized SQLite forensic tools for complete recovery."
            
            recovered_data['recovered'].append(table_data)
        
        conn.close()
        return recovered_data
    
    except Exception as e:
        logger.error(f"Error recovering deleted records from {db_path}: {e}")
        raise


def analyze_journal_files(db_path: str) -> Dict:
    """
    Analyze SQLite journal and WAL files for a database
    
    Args:
        db_path: Path to the SQLite database
        
    Returns:
        Dictionary with journal analysis results
    """
    logger.info(f"Analyzing journal files for {db_path}")
    
    if not is_sqlite_database(db_path):
        raise ValueError(f"Not a valid SQLite database: {db_path}")
    
    # Check for journal files
    journal_path = f"{db_path}-journal"
    wal_path = f"{db_path}-wal"
    shm_path = f"{db_path}-shm"
    
    journal_info = {
        'database': db_path,
        'has_journal': os.path.exists(journal_path),
        'has_wal': os.path.exists(wal_path),
        'has_shm': os.path.exists(shm_path),
        'journal_files': []
    }
    
    # Analyze journal file if it exists
    if journal_info['has_journal']:
        journal_data = {
            'path': journal_path,
            'size': os.path.getsize(journal_path),
            'type': 'rollback-journal'
        }
        journal_info['journal_files'].append(journal_data)
    
    # Analyze WAL file if it exists
    if journal_info['has_wal']:
        wal_data = {
            'path': wal_path,
            'size': os.path.getsize(wal_path),
            'type': 'write-ahead log'
        }
        journal_info['journal_files'].append(wal_data)
    
    # Analyze SHM file if it exists
    if journal_info['has_shm']:
        shm_data = {
            'path': shm_path,
            'size': os.path.getsize(shm_path),
            'type': 'shared-memory file'
        }
        journal_info['journal_files'].append(shm_data)
    
    return journal_info
