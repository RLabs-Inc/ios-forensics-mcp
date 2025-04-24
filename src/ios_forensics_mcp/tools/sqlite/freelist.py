# tools/sqlite/freelist.py - SQLite freelist and deleted record recovery

import os
import struct
import sqlite3
import logging
import tempfile
import shutil
import re
from typing import Dict, List, Optional, Any, Tuple, Union, BinaryIO
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)


class SQLiteFreelistParser:
    """
    Parser for SQLite database freelist pages to recover deleted data
    
    SQLite stores deleted records in "freelist" pages that can be analyzed
    to recover previously deleted data.
    """
    
    # SQLite constants
    PAGE_HEADER_SIZE = 8       # Size of page header in bytes
    CELL_POINTER_SIZE = 2      # Size of cell pointer in bytes
    
    # SQLite B-tree page types
    BTREE_INTERIOR_INDEX = 2   # Interior index b-tree page
    BTREE_INTERIOR_TABLE = 5   # Interior table b-tree page
    BTREE_LEAF_INDEX = 10      # Leaf index b-tree page
    BTREE_LEAF_TABLE = 13      # Leaf table b-tree page
    
    def __init__(self, db_path: str):
        """
        Initialize the SQLite freelist parser
        
        Args:
            db_path: Path to the SQLite database
        """
        self.db_path = db_path
        
        # Get page size and other metadata from the database
        self.page_size = 0
        self.encoding = 'utf-8'
        self.free_pages = []
        self.tables = {}
        
        # Initialize database metadata
        self._init_database_metadata()
    
    def _init_database_metadata(self):
        """Initialize database metadata by reading the database header and tables"""
        try:
            # Create a temporary copy to prevent modification
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, os.path.basename(self.db_path))
            
            # Copy the database
            shutil.copy2(self.db_path, temp_db_path)
            
            # Check for WAL file
            wal_path = f"{self.db_path}-wal"
            if os.path.exists(wal_path):
                temp_wal_path = f"{temp_db_path}-wal"
                shutil.copy2(wal_path, temp_wal_path)
            
            # Open with URI for read-only access
            uri = f"file:{temp_db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            
            # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
            conn.execute("PRAGMA journal_mode=OFF")
            
            # Disable WAL mode to prevent modification
            conn.execute("PRAGMA locking_mode=NORMAL")
            
            cursor = conn.cursor()
            
            # Get page size
            cursor.execute("PRAGMA page_size")
            self.page_size = cursor.fetchone()[0]
            
            # Get encoding
            cursor.execute("PRAGMA encoding")
            self.encoding = cursor.fetchone()[0]
            
            # Get freelist info
            cursor.execute("PRAGMA freelist_count")
            freelist_count = cursor.fetchone()[0]
            
            # Get table information
            cursor.execute("SELECT name, rootpage FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            for name, rootpage in cursor.fetchall():
                # Get table schema
                cursor.execute(f"PRAGMA table_info({name})")
                columns = []
                for cid, column_name, column_type, not_null, default_value, pk in cursor.fetchall():
                    columns.append({
                        'cid': cid,
                        'name': column_name,
                        'type': column_type,
                        'not_null': not_null,
                        'default_value': default_value,
                        'pk': pk
                    })
                
                self.tables[name] = {
                    'rootpage': rootpage,
                    'columns': columns
                }
            
            conn.close()
            
            logger.info(f"Database metadata initialized: page_size={self.page_size}, encoding={self.encoding}, freelist_count={freelist_count}")
            
            # Also read the raw database header to get freelist trunk page
            self._read_database_header()
            
            # Clean up temporary files
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            os.rmdir(temp_dir)
        
        except Exception as e:
            logger.error(f"Error initializing database metadata: {e}")
            raise
    
    def _read_database_header(self):
        """Read the SQLite database header to get freelist information"""
        try:
            with open(self.db_path, 'rb') as f:
                # Read header (first 100 bytes)
                header_data = f.read(100)
                
                # Bytes 16-17: Size of the database page in bytes
                page_size = struct.unpack('>H', header_data[16:18])[0]
                if page_size == 1:
                    # Page size is 65536 if stored as 1
                    page_size = 65536
                
                # Bytes 32-35: Page number of the first freelist trunk page
                freelist_trunk_page = struct.unpack('>I', header_data[32:36])[0]
                
                # Bytes 36-39: Total number of freelist pages
                total_freelist_pages = struct.unpack('>I', header_data[36:40])[0]
                
                logger.info(f"Database header: page_size={page_size}, freelist_trunk_page={freelist_trunk_page}, total_freelist_pages={total_freelist_pages}")
                
                # Store freelist information
                self.page_size = page_size if page_size > 0 else self.page_size
                
                # If there are freelist pages, collect them
                if freelist_trunk_page > 0 and total_freelist_pages > 0:
                    self._collect_freelist_pages(freelist_trunk_page)
        
        except Exception as e:
            logger.error(f"Error reading database header: {e}")
    
    def _collect_freelist_pages(self, trunk_page: int):
        """
        Collect all pages in the freelist
        
        Args:
            trunk_page: First freelist trunk page number
        """
        try:
            with open(self.db_path, 'rb') as f:
                # Navigate to the trunk page
                f.seek((trunk_page - 1) * self.page_size)
                
                # Read trunk page header
                trunk_data = f.read(8)
                
                # First 4 bytes: Page type (should be 0 for freelist trunk)
                page_type = struct.unpack('>I', trunk_data[0:4])[0]
                
                # Next 4 bytes: Number of leaf pages in this trunk
                num_leaves = struct.unpack('>I', trunk_data[4:8])[0]
                
                logger.info(f"Freelist trunk page {trunk_page}: page_type={page_type}, num_leaves={num_leaves}")
                
                # Add trunk page to freelist
                self.free_pages.append(trunk_page)
                
                # Read leaf page numbers (each is 4 bytes)
                for i in range(num_leaves):
                    leaf_page_offset = 8 + (i * 4)
                    if leaf_page_offset + 4 <= self.page_size:
                        f.seek((trunk_page - 1) * self.page_size + leaf_page_offset)
                        leaf_page = struct.unpack('>I', f.read(4))[0]
                        if leaf_page > 0:
                            self.free_pages.append(leaf_page)
                
                # Check if there's another trunk page
                next_trunk_offset = 8 + (num_leaves * 4)
                if next_trunk_offset + 4 <= self.page_size:
                    f.seek((trunk_page - 1) * self.page_size + next_trunk_offset)
                    next_trunk = struct.unpack('>I', f.read(4))[0]
                    if next_trunk > 0:
                        # Recursively collect pages from next trunk
                        self._collect_freelist_pages(next_trunk)
        
        except Exception as e:
            logger.error(f"Error collecting freelist pages: {e}")
    
    def scan_freelist(self) -> Dict[str, Any]:
        """
        Scan freelist pages for recoverable data
        
        Returns:
            Dictionary with scan results
        """
        logger.info(f"Scanning freelist pages in {self.db_path}")
        
        scan_results = {
            'db_path': self.db_path,
            'page_size': self.page_size,
            'encoding': self.encoding,
            'free_page_count': len(self.free_pages),
            'recovered_data': []
        }
        
        try:
            with open(self.db_path, 'rb') as f:
                # Scan each free page
                for page_num in self.free_pages:
                    # Skip page 1 (database header)
                    if page_num <= 1:
                        continue
                    
                    # Read the page
                    f.seek((page_num - 1) * self.page_size)
                    page_data = f.read(self.page_size)
                    
                    # Analyze the page
                    page_type = self._get_page_type(page_data)
                    
                    page_result = {
                        'page_number': page_num,
                        'page_type': page_type,
                        'recovered_records': []
                    }
                    
                    # If this is a leaf table page, try to recover records
                    if page_type == self.BTREE_LEAF_TABLE:
                        records = self._extract_records_from_page(page_data)
                        page_result['recovered_records'] = records
                    
                    # Add text fragments found on the page
                    text_fragments = self._extract_text_fragments(page_data)
                    if text_fragments:
                        page_result['text_fragments'] = text_fragments
                    
                    scan_results['recovered_data'].append(page_result)
            
            logger.info(f"Scanned {len(self.free_pages)} freelist pages")
            return scan_results
        
        except Exception as e:
            logger.error(f"Error scanning freelist: {e}")
            return scan_results
    
    def _get_page_type(self, page_data: bytes) -> int:
        """
        Determine the type of a database page
        
        Args:
            page_data: Raw page data
            
        Returns:
            Page type constant or 0 if unknown
        """
        if len(page_data) < 8:
            return 0
        
        # First byte is the page type
        page_type = page_data[0]
        
        # Convert to our constants
        if page_type == 2:
            return self.BTREE_INTERIOR_INDEX
        elif page_type == 5:
            return self.BTREE_INTERIOR_TABLE
        elif page_type == 10:
            return self.BTREE_LEAF_INDEX
        elif page_type == 13:
            return self.BTREE_LEAF_TABLE
        else:
            return 0
    
    def _extract_records_from_page(self, page_data: bytes) -> List[Dict[str, Any]]:
        """
        Extract records from a leaf table page
        
        Args:
            page_data: Raw page data
            
        Returns:
            List of recovered record dictionaries
        """
        records = []
        
        # Check if this is a leaf table page
        if len(page_data) < 8 or page_data[0] != 13:
            return records
        
        try:
            # Get header information
            header_size = 8
            
            # Byte 1: Flags
            flags = page_data[1]
            
            # Bytes 3-4: Number of cells on this page
            num_cells = struct.unpack('>H', page_data[3:5])[0]
            
            # Bytes 5-6: Offset to first cell content
            first_cell_offset = struct.unpack('>H', page_data[5:7])[0]
            
            # Extract cell pointers (2 bytes each, pointing to cell content)
            cell_pointers = []
            for i in range(num_cells):
                pointer_offset = header_size + (i * 2)
                if pointer_offset + 2 <= len(page_data):
                    cell_offset = struct.unpack('>H', page_data[pointer_offset:pointer_offset+2])[0]
                    if 0 < cell_offset < self.page_size:
                        cell_pointers.append(cell_offset)
            
            # Process each cell
            for cell_offset in cell_pointers:
                if cell_offset >= len(page_data):
                    continue
                
                # Extract record data
                record = self._parse_cell(page_data, cell_offset)
                if record:
                    records.append(record)
        
        except Exception as e:
            logger.warning(f"Error extracting records from page: {e}")
        
        return records
    
    def _parse_cell(self, page_data: bytes, cell_offset: int) -> Optional[Dict[str, Any]]:
        """
        Parse a cell to extract record data
        
        Args:
            page_data: Raw page data
            cell_offset: Offset to the cell within the page
            
        Returns:
            Dictionary with record data or None if parsing fails
        """
        try:
            # First field is the payload size (varint)
            payload_size, varint_size = self._decode_varint(page_data, cell_offset)
            if payload_size <= 0:
                return None
            
            # Next field is the rowid (varint)
            rowid, rowid_varint_size = self._decode_varint(page_data, cell_offset + varint_size)
            
            # Calculate header size
            header_offset = cell_offset + varint_size + rowid_varint_size
            
            # Try to parse the record header and payload
            record = {
                'rowid': rowid,
                'payload_size': payload_size,
                'values': {}
            }
            
            # Extract some data as fields (simplified)
            payload_offset = header_offset
            
            # Just extract any textual data we can find
            payload_end = min(payload_offset + payload_size, len(page_data))
            payload_data = page_data[payload_offset:payload_end]
            
            # Try to detect text fields
            text_values = self._extract_text_from_payload(payload_data)
            if text_values:
                record['values'] = text_values
            
            return record
        
        except Exception as e:
            logger.warning(f"Error parsing cell: {e}")
            return None
    
    def _decode_varint(self, data: bytes, offset: int) -> Tuple[int, int]:
        """
        Decode a variable-length integer
        
        Args:
            data: Raw data
            offset: Offset to the varint
            
        Returns:
            Tuple of (value, bytes_read)
        """
        value = 0
        for i in range(9):  # SQLite varints are at most 9 bytes
            if offset + i >= len(data):
                break
            
            byte = data[offset + i]
            value = (value << 7) | (byte & 0x7F)
            
            if not (byte & 0x80):
                return value, i + 1
        
        # If we get here, something went wrong
        return 0, 1
    
    def _extract_text_from_payload(self, payload_data: bytes) -> Dict[str, str]:
        """
        Extract text strings from record payload
        
        Args:
            payload_data: Raw payload data
            
        Returns:
            Dictionary mapping field indices to text values
        """
        text_values = {}
        
        # Try to identify text strings in the payload
        for encoding in [self.encoding, 'utf-8', 'utf-16', 'ascii', 'latin1']:
            try:
                # Convert to string
                text = payload_data.decode(encoding, errors='ignore')
                
                # Split into potential fields
                for i, part in enumerate(re.split(r'[\x00-\x1F\x7F-\xFF]+', text)):
                    # Keep only parts that look like text
                    if len(part) >= 3 and re.search(r'[a-zA-Z0-9]', part):
                        text_values[f'field_{i}'] = part
                
                # If we found text, stop trying different encodings
                if text_values:
                    break
            except Exception:
                continue
        
        return text_values
    
    def _extract_text_fragments(self, page_data: bytes) -> List[str]:
        """
        Extract text fragments from page data
        
        Args:
            page_data: Raw page data
            
        Returns:
            List of text fragments
        """
        fragments = []
        
        # Try different encodings
        for encoding in [self.encoding, 'utf-8', 'utf-16', 'ascii', 'latin1']:
            try:
                # Convert to string
                text = page_data.decode(encoding, errors='ignore')
                
                # Find text fragments (at least 4 printable chars)
                for match in re.finditer(r'[ -~]{4,}', text):
                    fragment = match.group()
                    
                    # Keep only fragments that look meaningful
                    if len(fragment) >= 4 and re.search(r'[a-zA-Z0-9]', fragment):
                        fragments.append(fragment)
                
                # If we found fragments, stop trying different encodings
                if fragments:
                    break
            except Exception:
                continue
        
        return fragments


def recover_deleted_records(db_path: str, table_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Recover deleted records from a SQLite database
    
    Args:
        db_path: Path to the SQLite database
        table_name: Optional table name to focus recovery
        
    Returns:
        Dictionary with recovered records
    """
    logger.info(f"Recovering deleted records from {db_path}")
    
    try:
        parser = SQLiteFreelistParser(db_path)
        scan_results = parser.scan_freelist()
        
        # Organize results by potential table
        recovery_results = {
            'db_path': db_path,
            'tables': [],
            'recovered_count': 0,
            'text_fragments': []
        }
        
        # Collect all text fragments
        all_fragments = []
        for page_result in scan_results.get('recovered_data', []):
            # Add records
            for record in page_result.get('recovered_records', []):
                # Create a recovery entry
                recovery_entry = {
                    'rowid': record.get('rowid'),
                    'page_number': page_result.get('page_number'),
                    'values': record.get('values', {})
                }
                
                # Add to recovery results
                recovery_results['recovered_count'] += 1
                
                # Try to determine which table this belongs to
                table_name = 'unknown'
                recovery_results['tables'].append({
                    'name': table_name,
                    'records': [recovery_entry]
                })
            
            # Add text fragments
            for fragment in page_result.get('text_fragments', []):
                if fragment not in all_fragments:
                    all_fragments.append(fragment)
        
        # Sort fragments by length (longest first) and add to results
        all_fragments.sort(key=len, reverse=True)
        recovery_results['text_fragments'] = all_fragments[:100]  # Limit to 100 fragments
        
        return recovery_results
    
    except Exception as e:
        logger.error(f"Error recovering deleted records: {e}")
        return {
            'db_path': db_path,
            'error': str(e),
            'tables': [],
            'recovered_count': 0,
            'text_fragments': []
        }


def carve_deleted_tables(db_path: str) -> Dict[str, Any]:
    """
    Carve deleted tables from SQLite database file
    
    This is a more aggressive approach that scans the entire database file
    for table structures regardless of the current freelist
    
    Args:
        db_path: Path to the SQLite database
        
    Returns:
        Dictionary with carved tables
    """
    logger.info(f"Carving deleted tables from {db_path}")
    
    try:
        # Read the database file
        with open(db_path, 'rb') as f:
            db_data = f.read()
        
        # Look for SQLite leaf table pages (header byte 0x0D = 13)
        page_size = 0
        
        # Try to get page size from database header
        if len(db_data) >= 16:
            header_page_size = struct.unpack('>H', db_data[16:18])[0]
            if header_page_size == 1:
                page_size = 65536
            elif header_page_size >= 512:
                page_size = header_page_size
        
        # If we couldn't get page size from header, use common sizes
        if page_size == 0:
            # Try common page sizes
            for size in [4096, 8192, 16384, 32768, 1024, 2048, 512]:
                if len(db_data) % size == 0:
                    page_size = size
                    break
        
        # If we still don't have a page size, default to 4096
        if page_size == 0:
            page_size = 4096
        
        logger.info(f"Using page size: {page_size}")
        
        # Results structure
        carving_results = {
            'db_path': db_path,
            'page_size': page_size,
            'carved_pages': [],
            'text_fragments': []
        }
        
        # Scan the file for leaf table pages
        page_count = len(db_data) // page_size
        all_fragments = []
        
        for i in range(page_count):
            page_offset = i * page_size
            page_data = db_data[page_offset:page_offset + page_size]
            
            # Check for leaf table page marker (0x0D)
            if len(page_data) > 0 and page_data[0] == 13:
                # This looks like a leaf table page
                parser = SQLiteFreelistParser(db_path)
                records = parser._extract_records_from_page(page_data)
                
                if records:
                    carved_page = {
                        'page_offset': page_offset,
                        'page_index': i + 1,
                        'records': records
                    }
                    carving_results['carved_pages'].append(carved_page)
            
            # Extract text fragments from every page
            text_fragments = SQLiteFreelistParser(db_path)._extract_text_fragments(page_data)
            for fragment in text_fragments:
                if fragment not in all_fragments:
                    all_fragments.append(fragment)
        
        # Sort fragments by length (longest first) and add to results
        all_fragments.sort(key=len, reverse=True)
        carving_results['text_fragments'] = all_fragments[:100]  # Limit to 100 fragments
        
        return carving_results
    
    except Exception as e:
        logger.error(f"Error carving deleted tables: {e}")
        return {
            'db_path': db_path,
            'error': str(e),
            'carved_pages': [],
            'text_fragments': []
        }
