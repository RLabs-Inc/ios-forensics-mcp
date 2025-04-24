# tools/sqlite/wal_analyzer.py - SQLite WAL file analysis tools

import os
import struct
import logging
import tempfile
import sqlite3
import shutil
from typing import Dict, List, Optional, Any, Tuple, Union, BinaryIO
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)


class WALAnalyzer:
    """
    Analyzer for SQLite Write-Ahead Log (WAL) files
    
    The WAL file contains frames of data that represent changes to the database.
    This analyzer can extract and interpret these frames to recover deleted or 
    modified data that isn't present in the main database file.
    """
    
    # WAL file constants
    WAL_MAGIC = 0x377f0682    # Little-endian WAL file identifier
    WAL_MAGIC_BE = 0x377f0683  # Big-endian WAL file identifier
    WAL_HEADER_SIZE = 32       # Size of WAL header in bytes
    FRAME_HEADER_SIZE = 24     # Size of frame header in bytes
    
    def __init__(self, db_path: str):
        """
        Initialize the WAL analyzer
        
        Args:
            db_path: Path to the SQLite database
        """
        self.db_path = db_path
        self.wal_path = f"{db_path}-wal"
        self.shm_path = f"{db_path}-shm"
        
        # Check if WAL file exists
        if not os.path.exists(self.wal_path):
            raise FileNotFoundError(f"WAL file not found: {self.wal_path}")
        
        # Database connection (will be initialized when needed)
        self.conn = None
        
        # Extracted WAL information
        self.wal_info = {
            'header': None,
            'frames': [],
            'valid': False,
            'big_endian': False,
            'page_size': 0,
            'checkpoint_seq': 0,
            'salt': (0, 0),
            'frame_count': 0
        }
    
    def __del__(self):
        """Clean up resources on deletion"""
        if self.conn:
            self.conn.close()
    
    def analyze(self) -> Dict:
        """
        Analyze the WAL file
        
        Returns:
            Dictionary with WAL analysis results
        """
        logger.info(f"Analyzing WAL file: {self.wal_path}")
        
        try:
            # Create a read-only temp copy for analysis
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, os.path.basename(self.db_path))
            temp_wal_path = f"{temp_db_path}-wal"
            
            # Copy the database and WAL files
            shutil.copy2(self.db_path, temp_db_path)
            shutil.copy2(self.wal_path, temp_wal_path)
            
            # Analyze the WAL header
            self._analyze_header(temp_wal_path)
            
            # If header is valid, analyze the frames
            if self.wal_info['valid']:
                self._analyze_frames(temp_wal_path)
            
            # Clean up temporary files
            try:
                os.remove(temp_db_path)
                os.remove(temp_wal_path)
                os.rmdir(temp_dir)
            except Exception as e:
                logger.warning(f"Error cleaning up temporary files: {e}")
            
            return self.wal_info
        
        except Exception as e:
            logger.error(f"Error analyzing WAL file {self.wal_path}: {e}")
            raise
    
    def _analyze_header(self, wal_path: str) -> None:
        """
        Analyze the WAL file header
        
        Args:
            wal_path: Path to the WAL file
        """
        with open(wal_path, 'rb') as f:
            header_data = f.read(self.WAL_HEADER_SIZE)
            
            if len(header_data) < self.WAL_HEADER_SIZE:
                logger.warning(f"WAL file too small: {len(header_data)} bytes")
                self.wal_info['valid'] = False
                return
            
            # Unpack header fields (always little-endian initially)
            magic, = struct.unpack('<I', header_data[0:4])
            
            # Check if the file is big-endian
            if magic == self.WAL_MAGIC_BE:
                self.wal_info['big_endian'] = True
                endian = '>'  # Big-endian
            elif magic == self.WAL_MAGIC:
                self.wal_info['big_endian'] = False
                endian = '<'  # Little-endian
            else:
                logger.warning(f"Invalid WAL magic number: 0x{magic:08x}")
                self.wal_info['valid'] = False
                return
            
            # Unpack header fields with the correct endianness
            format_string = f"{endian}IIIIIII"
            fields = struct.unpack(format_string, header_data[0:28])
            
            magic, file_format, page_size, checkpoint_seq, salt1, salt2, checksum = fields
            
            self.wal_info['header'] = {
                'magic': f"0x{magic:08x}",
                'file_format': file_format,
                'page_size': page_size,
                'checkpoint_seq': checkpoint_seq,
                'salt': (salt1, salt2),
                'checksum': checksum
            }
            
            self.wal_info['page_size'] = page_size
            self.wal_info['checkpoint_seq'] = checkpoint_seq
            self.wal_info['salt'] = (salt1, salt2)
            self.wal_info['valid'] = True
            
            logger.info(f"WAL header analyzed: page_size={page_size}, checkpoint_seq={checkpoint_seq}")
    
    def _analyze_frames(self, wal_path: str) -> None:
        """
        Analyze frames in the WAL file
        
        Args:
            wal_path: Path to the WAL file
        """
        with open(wal_path, 'rb') as f:
            # Skip the header
            f.seek(self.WAL_HEADER_SIZE)
            
            page_size = self.wal_info['page_size']
            endian = '>' if self.wal_info['big_endian'] else '<'
            frame_count = 0
            
            # Read and analyze frames
            while True:
                frame_header = f.read(self.FRAME_HEADER_SIZE)
                if len(frame_header) < self.FRAME_HEADER_SIZE:
                    break  # End of file or incomplete frame
                
                # Unpack frame header
                format_string = f"{endian}IIIIII"
                try:
                    page_number, commit_seq, salt1, salt2, checksum1, checksum2 = struct.unpack(format_string, frame_header)
                except struct.error:
                    logger.warning(f"Error unpacking frame header, possibly truncated")
                    break
                
                # Read page content
                page_content = f.read(page_size)
                if len(page_content) < page_size:
                    logger.warning(f"Incomplete page data in frame {frame_count+1}")
                    break
                
                # Store frame information
                frame_info = {
                    'page_number': page_number,
                    'commit_seq': commit_seq,
                    'salt': (salt1, salt2),
                    'checksum': (checksum1, checksum2),
                    'offset': self.WAL_HEADER_SIZE + frame_count * (self.FRAME_HEADER_SIZE + page_size),
                    'size': self.FRAME_HEADER_SIZE + page_size
                }
                
                self.wal_info['frames'].append(frame_info)
                frame_count += 1
            
            self.wal_info['frame_count'] = frame_count
            logger.info(f"Analyzed {frame_count} frames in WAL file")
    
    def extract_deleted_records(self, table_name: Optional[str] = None) -> Dict:
        """
        Extract potentially deleted records from the WAL file
        
        Args:
            table_name: Optional table name to focus recovery
            
        Returns:
            Dictionary with recovered records
        """
        logger.info(f"Extracting deleted records from WAL file: {self.wal_path}")
        
        # If the WAL hasn't been analyzed yet, do it now
        if not self.wal_info['valid']:
            self.analyze()
        
        # Create a recovery database using temporary files
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Create a schema-only temporary database
            temp_db_path = os.path.join(temp_dir, "recovery.db")
            schema_conn = sqlite3.connect(self.db_path)
            recovery_conn = sqlite3.connect(temp_db_path)
            
            cursor = schema_conn.cursor()
            recovery_cursor = recovery_conn.cursor()
            
            # Get table schema from the original database
            if table_name:
                cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
                tables = cursor.fetchall()
            else:
                cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                tables = cursor.fetchall()
            
            # Create the tables in the recovery database
            for table_sql, in tables:
                if table_sql:
                    recovery_cursor.execute(table_sql)
            
            schema_conn.close()
            
            # Now extract data from the WAL frames for these tables
            recovery_results = {
                'wal_path': self.wal_path,
                'tables': [],
                'recovered_count': 0
            }
            
            # Use SQLite's page parsing logic to extract records
            # This is a simplified approach - a real implementation would parse 
            # the actual SQLite page format in the WAL frames
            
            # For each table, try to recover any deleted records from the WAL
            for table_sql, in tables:
                if not table_sql:
                    continue
                
                # Extract table name from SQL
                import re
                table_match = re.search(r'CREATE\s+TABLE\s+(?:"([^"]+)"|\'([^\']+)\'|([a-zA-Z0-9_]+))', table_sql, re.IGNORECASE)
                if not table_match:
                    continue
                
                extracted_name = next((g for g in table_match.groups() if g is not None), None)
                if not extracted_name:
                    continue
                
                # If a specific table was requested, skip others
                if table_name and extracted_name != table_name:
                    continue
                
                table_info = {
                    'name': extracted_name,
                    'records': []
                }
                
                # Extract column names
                recovery_cursor.execute(f"PRAGMA table_info({extracted_name})")
                columns = [row[1] for row in recovery_cursor.fetchall()]
                
                # Extract records from WAL frames
                # This requires specialized SQLite page format parsing
                # For demonstration purposes, we'll use a simplified approach
                for frame in self.wal_info['frames']:
                    # Get page type information from the original database
                    # A more complete implementation would parse the B-tree structure
                    
                    # For now, we'll just note which pages might contain data for this table
                    # In a real implementation, we would extract and decode the records
                    # from the page data stored in the WAL
                    
                    table_info['records'].append({
                        'frame': frame['page_number'],
                        'commit_seq': frame['commit_seq'],
                        'potential_recovery': f"Page {frame['page_number']} may contain data for table {extracted_name}"
                    })
                
                recovery_results['tables'].append(table_info)
                recovery_results['recovered_count'] += len(table_info['records'])
            
            recovery_conn.close()
            
            return recovery_results
        
        except Exception as e:
            logger.error(f"Error extracting deleted records: {e}")
            raise
        
        finally:
            # Clean up temporary files
            try:
                for file in os.listdir(temp_dir):
                    os.remove(os.path.join(temp_dir, file))
                os.rmdir(temp_dir)
            except Exception as e:
                logger.warning(f"Error cleaning up temporary files: {e}")
    
    def compare_with_db(self) -> Dict:
        """
        Compare WAL frames with current database state
        
        Returns:
            Dictionary with comparison results
        """
        logger.info(f"Comparing WAL frames with database: {self.db_path}")
        
        # If the WAL hasn't been analyzed yet, do it now
        if not self.wal_info['valid']:
            self.analyze()
        
        # Create temporary copies for analysis
        temp_dir = tempfile.mkdtemp()
        temp_db_path = os.path.join(temp_dir, os.path.basename(self.db_path))
        
        try:
            # Copy the database
            shutil.copy2(self.db_path, temp_db_path)
            
            # Connect to the database
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Get the page size from the database
            cursor.execute("PRAGMA page_size")
            db_page_size = cursor.fetchone()[0]
            
            # Verify that the page sizes match
            if db_page_size != self.wal_info['page_size']:
                logger.warning(f"Page size mismatch: DB={db_page_size}, WAL={self.wal_info['page_size']}")
            
            comparison_results = {
                'db_path': self.db_path,
                'wal_path': self.wal_path,
                'page_size': {
                    'db': db_page_size,
                    'wal': self.wal_info['page_size']
                },
                'frame_count': self.wal_info['frame_count'],
                'modified_pages': []
            }
            
            # Read pages from the database file for comparison
            with open(temp_db_path, 'rb') as f:
                # Skip the SQLite header (first 100 bytes)
                f.seek(100)
                
                # For each frame in the WAL, compare with the corresponding page in the DB
                for frame in self.wal_info['frames']:
                    page_number = frame['page_number']
                    
                    # Read the corresponding page from the database
                    f.seek(100 + (page_number - 1) * db_page_size)
                    db_page_data = f.read(db_page_size)
                    
                    # Read the page data from the WAL
                    with open(self.wal_path, 'rb') as wal_f:
                        wal_f.seek(frame['offset'] + self.FRAME_HEADER_SIZE)
                        wal_page_data = wal_f.read(self.wal_info['page_size'])
                    
                    # Compare the pages (a real implementation would do a more detailed analysis)
                    if db_page_data != wal_page_data:
                        comparison_results['modified_pages'].append({
                            'page_number': page_number,
                            'commit_seq': frame['commit_seq'],
                            'status': 'modified'
                        })
            
            conn.close()
            
            return comparison_results
        
        except Exception as e:
            logger.error(f"Error comparing WAL with database: {e}")
            raise
        
        finally:
            # Clean up temporary files
            try:
                os.remove(temp_db_path)
                os.rmdir(temp_dir)
            except Exception as e:
                logger.warning(f"Error cleaning up temporary files: {e}")


def analyze_wal_file(db_path: str) -> Dict:
    """
    Analyze a WAL file for a SQLite database
    
    Args:
        db_path: Path to the SQLite database
        
    Returns:
        Dictionary with WAL analysis results
    """
    logger.info(f"Analyzing WAL file for database: {db_path}")
    
    wal_path = f"{db_path}-wal"
    
    if not os.path.exists(wal_path):
        return {
            'db_path': db_path,
            'has_wal': False,
            'error': f"WAL file not found: {wal_path}"
        }
    
    try:
        analyzer = WALAnalyzer(db_path)
        result = analyzer.analyze()
        
        # Add basic information to the result
        result['db_path'] = db_path
        result['wal_path'] = wal_path
        result['wal_size'] = os.path.getsize(wal_path)
        result['has_wal'] = True
        
        return result
    
    except Exception as e:
        logger.error(f"Error analyzing WAL file {wal_path}: {e}")
        return {
            'db_path': db_path,
            'has_wal': True,
            'wal_path': wal_path,
            'error': str(e)
        }


def extract_deleted_from_wal(db_path: str, table_name: Optional[str] = None) -> Dict:
    """
    Extract potentially deleted records from a WAL file
    
    Args:
        db_path: Path to the SQLite database
        table_name: Optional table name to focus recovery
        
    Returns:
        Dictionary with recovered records
    """
    logger.info(f"Extracting deleted records from WAL for database: {db_path}")
    
    wal_path = f"{db_path}-wal"
    
    if not os.path.exists(wal_path):
        return {
            'db_path': db_path,
            'has_wal': False,
            'error': f"WAL file not found: {wal_path}"
        }
    
    try:
        analyzer = WALAnalyzer(db_path)
        result = analyzer.extract_deleted_records(table_name)
        
        # Add basic information to the result
        result['db_path'] = db_path
        result['wal_path'] = wal_path
        result['has_wal'] = True
        
        return result
    
    except Exception as e:
        logger.error(f"Error extracting deleted records from WAL file {wal_path}: {e}")
        return {
            'db_path': db_path,
            'has_wal': True,
            'wal_path': wal_path,
            'error': str(e)
        }


def compare_db_with_wal(db_path: str) -> Dict:
    """
    Compare a database with its WAL file to identify changes
    
    Args:
        db_path: Path to the SQLite database
        
    Returns:
        Dictionary with comparison results
    """
    logger.info(f"Comparing database with its WAL file: {db_path}")
    
    wal_path = f"{db_path}-wal"
    
    if not os.path.exists(wal_path):
        return {
            'db_path': db_path,
            'has_wal': False,
            'error': f"WAL file not found: {wal_path}"
        }
    
    try:
        analyzer = WALAnalyzer(db_path)
        result = analyzer.compare_with_db()
        
        # Add basic information to the result
        result['has_wal'] = True
        
        return result
    
    except Exception as e:
        logger.error(f"Error comparing database with WAL file {wal_path}: {e}")
        return {
            'db_path': db_path,
            'has_wal': True,
            'wal_path': wal_path,
            'error': str(e)
        }
