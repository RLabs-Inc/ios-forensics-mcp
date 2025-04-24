# tools/specialized/messages.py - iOS Messages analysis tools

import os
import sqlite3
import logging
import tempfile
import shutil
import json
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)

# Import tools
from tools.sqlite.analyzer import is_sqlite_database


def find_message_databases(ios_root: str) -> List[Dict]:
    """
    Find SMS/iMessage databases in the iOS file system
    
    Args:
        ios_root: iOS file system root directory
        
    Returns:
        List of dictionaries with database information
    """
    logger.info(f"Searching for message databases in {ios_root}")
    
    # Known locations for SMS/iMessage databases
    known_locations = [
        os.path.join(ios_root, "private/var/mobile/Library/SMS/sms.db"),
        os.path.join(ios_root, "private/var/mobile/Library/SMS/chat.db"),
        os.path.join(ios_root, "private/var/mobile/Library/Messages/sms.db"),
        # iOS 5-7
        os.path.join(ios_root, "private/var/mobile/Library/Messages/SMS.db"),
        # iOS 16+
        os.path.join(ios_root, "private/var/mobile/Library/Messages/chat.db")
    ]
    
    # Check Shared AppGroup containers for iOS 10+
    app_groups_path = os.path.join(ios_root, "private/var/mobile/Containers/Shared/AppGroup")
    if os.path.exists(app_groups_path) and os.path.isdir(app_groups_path):
        for app_group in os.listdir(app_groups_path):
            app_group_path = os.path.join(app_groups_path, app_group)
            if os.path.isdir(app_group_path):
                # Check for message database in this app group
                potential_db = os.path.join(app_group_path, "Library/SMS/sms.db")
                if os.path.exists(potential_db):
                    known_locations.append(potential_db)
                
                potential_db = os.path.join(app_group_path, "Library/Messages/chat.db")
                if os.path.exists(potential_db):
                    known_locations.append(potential_db)
    
    results = []
    
    for location in known_locations:
        if os.path.exists(location) and is_sqlite_database(location):
            # Get basic info about the database
            db_info = {
                'path': location,
                'name': os.path.basename(location),
                'size': os.path.getsize(location),
                'relative_path': os.path.relpath(location, ios_root)
            }
            
            # Check if there are associated WAL/SHM files
            wal_path = f"{location}-wal"
            shm_path = f"{location}-shm"
            
            db_info['has_wal'] = os.path.exists(wal_path)
            db_info['has_shm'] = os.path.exists(shm_path)
            
            if db_info['has_wal']:
                db_info['wal_size'] = os.path.getsize(wal_path)
            
            results.append(db_info)
    
    logger.info(f"Found {len(results)} message databases")
    return results


def analyze_messages(db_path: str, limit: int = 1000) -> Dict:
    """
    Analyze SMS/iMessage database
    
    Args:
        db_path: Path to the message database
        limit: Maximum number of messages to analyze
        
    Returns:
        Dictionary with message analysis results
    """
    logger.info(f"Analyzing messages in {db_path}")
    
    if not is_sqlite_database(db_path):
        raise ValueError(f"Not a valid SQLite database: {db_path}")
    
    try:
        # Create a temporary copy of the database for forensic integrity
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
        uri = f"file:{temp_db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        
        # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
        conn.execute("PRAGMA journal_mode=OFF")
        
        # Disable WAL mode to prevent modification
        conn.execute("PRAGMA locking_mode=NORMAL")
        
        cursor = conn.cursor()
        
        # Determine database schema version
        db_version = _determine_message_db_version(cursor)
        
        analysis_results = {
            'db_path': db_path,
            'db_version': db_version,
            'messages': [],
            'conversations': [],
            'attachments': [],
            'statistics': {},
            'used_temp_copy': True
        }
        
        # Analyze based on database version
        if db_version == 'modern':  # iOS 6+ schema
            analysis_results['messages'] = _analyze_modern_messages(cursor, limit)
            analysis_results['conversations'] = _analyze_modern_conversations(cursor)
            analysis_results['attachments'] = _analyze_modern_attachments(cursor, limit)
        elif db_version == 'legacy':  # iOS 5 and earlier
            analysis_results['messages'] = _analyze_legacy_messages(cursor, limit)
            # Legacy database doesn't have dedicated conversation tracking
            analysis_results['conversations'] = _infer_legacy_conversations(analysis_results['messages'])
            analysis_results['attachments'] = _analyze_legacy_attachments(cursor, limit)
        else:
            analysis_results['error'] = f"Unknown message database schema version"
        
        # Generate statistics
        total_messages = len(analysis_results['messages'])
        total_conversations = len(analysis_results['conversations'])
        total_attachments = len(analysis_results['attachments'])
        
        # Message type distribution
        message_types = {}
        for msg in analysis_results['messages']:
            msg_type = msg.get('service', 'unknown')
            message_types[msg_type] = message_types.get(msg_type, 0) + 1
        
        # Date range
        date_range = {
            'min': None,
            'max': None
        }
        
        if total_messages > 0:
            dates = [msg.get('date') for msg in analysis_results['messages'] if msg.get('date')]
            if dates:
                date_range['min'] = min(dates)
                date_range['max'] = max(dates)
        
        # Attachment type distribution
        attachment_types = {}
        for att in analysis_results['attachments']:
            att_type = att.get('mime_type', 'unknown').split('/')[0]
            attachment_types[att_type] = attachment_types.get(att_type, 0) + 1
        
        analysis_results['statistics'] = {
            'total_messages': total_messages,
            'total_conversations': total_conversations,
            'total_attachments': total_attachments,
            'message_types': message_types,
            'date_range': date_range,
            'attachment_types': attachment_types
        }
        
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
        
        return analysis_results
    
    except Exception as e:
        logger.error(f"Error analyzing messages in {db_path}: {e}")
        raise


def _determine_message_db_version(cursor: sqlite3.Cursor) -> str:
    """
    Determine the version of the message database schema
    
    Args:
        cursor: SQLite database cursor
        
    Returns:
        Schema version identifier ('modern', 'legacy', or 'unknown')
    """
    # Check for tables in modern schema (iOS 6+)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='message'")
    has_message_table = cursor.fetchone() is not None
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chat'")
    has_chat_table = cursor.fetchone() is not None
    
    # Check for tables in legacy schema (iOS 5 and earlier)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
    has_messages_table = cursor.fetchone() is not None
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='msg_group'")
    has_msg_group_table = cursor.fetchone() is not None
    
    if has_message_table and has_chat_table:
        return 'modern'
    elif has_messages_table and has_msg_group_table:
        return 'legacy'
    else:
        # Try to make a best guess
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        if 'message' in tables:
            return 'modern'
        elif 'messages' in tables:
            return 'legacy'
        else:
            return 'unknown'


def _analyze_modern_messages(cursor: sqlite3.Cursor, limit: int) -> List[Dict]:
    """
    Analyze messages in the modern schema (iOS 6+)
    
    Args:
        cursor: SQLite database cursor
        limit: Maximum number of messages to analyze
        
    Returns:
        List of dictionaries with message information
    """
    messages = []
    
    try:
        # Check if the handle table exists (iOS 9+)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='handle'")
        has_handle_table = cursor.fetchone() is not None
        
        if has_handle_table:
            # Modern schema with handle table (iOS 9+)
            query = """
                SELECT
                    m.ROWID as message_id,
                    m.date as timestamp,
                    h.id as contact_id,
                    m.text as body,
                    m.service as service,
                    m.is_from_me as is_from_me,
                    m.is_read as is_read,
                    m.is_delivered as is_delivered,
                    m.date_read as date_read,
                    m.date_delivered as date_delivered,
                    c.chat_identifier as conversation_id,
                    m.associated_message_guid as reply_to_guid,
                    m.cache_has_attachments as has_attachments
                FROM
                    message as m
                LEFT JOIN
                    handle as h ON m.handle_id = h.ROWID
                LEFT JOIN
                    chat_message_join as cmj ON m.ROWID = cmj.message_id
                LEFT JOIN
                    chat as c ON cmj.chat_id = c.ROWID
                ORDER BY
                    m.date DESC
                LIMIT ?
            """
        else:
            # Modern schema without handle table (iOS 6-8)
            query = """
                SELECT
                    m.ROWID as message_id,
                    m.date as timestamp,
                    m.address as contact_id,
                    m.text as body,
                    m.service as service,
                    m.is_from_me as is_from_me,
                    m.is_read as is_read,
                    m.is_delivered as is_delivered,
                    m.date_read as date_read,
                    m.date_delivered as date_delivered,
                    c.chat_identifier as conversation_id,
                    m.cache_has_attachments as has_attachments
                FROM
                    message as m
                LEFT JOIN
                    chat_message_join as cmj ON m.ROWID = cmj.message_id
                LEFT JOIN
                    chat as c ON cmj.chat_id = c.ROWID
                ORDER BY
                    m.date DESC
                LIMIT ?
            """
        
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        
        for row in rows:
            message = dict(row)
            
            # Convert timestamps
            if message.get('timestamp'):
                # iOS timestamps are in Mac Absolute Time (seconds since 2001-01-01)
                # Convert to Unix timestamp (seconds since 1970-01-01)
                mac_absolute_time = message['timestamp']
                if mac_absolute_time:
                    unix_timestamp = mac_absolute_time + 978307200  # Offset between epochs
                    message['date'] = datetime.fromtimestamp(unix_timestamp / 1e9).isoformat()
                    message['timestamp_unix'] = unix_timestamp
            
            if message.get('date_read'):
                date_read = message['date_read']
                if date_read:
                    unix_timestamp = date_read + 978307200
                    message['date_read_formatted'] = datetime.fromtimestamp(unix_timestamp / 1e9).isoformat()
            
            if message.get('date_delivered'):
                date_delivered = message['date_delivered']
                if date_delivered:
                    unix_timestamp = date_delivered + 978307200
                    message['date_delivered_formatted'] = datetime.fromtimestamp(unix_timestamp / 1e9).isoformat()
            
            # Clean up binary data in text
            if message.get('body') and isinstance(message['body'], bytes):
                try:
                    message['body'] = message['body'].decode('utf-8', errors='replace')
                except Exception:
                    message['body'] = f"<binary data: {len(message['body'])} bytes>"
            
            # Make boolean values actual booleans
            for key in ['is_from_me', 'is_read', 'is_delivered', 'has_attachments']:
                if key in message and message[key] is not None:
                    message[key] = bool(message[key])
            
            messages.append(message)
    
    except Exception as e:
        logger.error(f"Error analyzing modern messages: {e}")
        # Try a simplified query as fallback
        try:
            cursor.execute("SELECT * FROM message ORDER BY date DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            
            for row in rows:
                messages.append(dict(row))
        except Exception as e2:
            logger.error(f"Error with fallback message query: {e2}")
    
    return messages


def _analyze_modern_conversations(cursor: sqlite3.Cursor) -> List[Dict]:
    """
    Analyze conversations in the modern schema (iOS 6+)
    
    Args:
        cursor: SQLite database cursor
        
    Returns:
        List of dictionaries with conversation information
    """
    conversations = []
    
    try:
        query = """
            SELECT
                c.ROWID as conversation_id,
                c.chat_identifier as identifier,
                c.display_name as display_name,
                c.service_name as service,
                c.is_archived as is_archived,
                c.last_addressed_handle as last_contacted_id,
                COUNT(cmj.message_id) as message_count
            FROM
                chat as c
            LEFT JOIN
                chat_message_join as cmj ON c.ROWID = cmj.chat_id
            GROUP BY
                c.ROWID
            ORDER BY
                c.last_addressed_timestamp DESC
        """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        
        for row in rows:
            conversation = dict(row)
            
            # Make boolean values actual booleans
            for key in ['is_archived']:
                if key in conversation and conversation[key] is not None:
                    conversation[key] = bool(conversation[key])
            
            # Get participants
            try:
                # Check if handle_join is available
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chat_handle_join'")
                has_chat_handle_join = cursor.fetchone() is not None
                
                if has_chat_handle_join:
                    # iOS 9+ schema
                    cursor.execute("""
                        SELECT
                            h.id as identifier,
                            h.service as service,
                            h.country as country
                        FROM
                            handle as h
                        JOIN
                            chat_handle_join as chj ON h.ROWID = chj.handle_id
                        WHERE
                            chj.chat_id = ?
                    """, (conversation['conversation_id'],))
                    
                    participants = [dict(row) for row in cursor.fetchall()]
                    conversation['participants'] = participants
                else:
                    # Earlier iOS versions don't have a direct participants table
                    conversation['participants'] = []
            except Exception as e:
                logger.warning(f"Error getting conversation participants: {e}")
                conversation['participants'] = []
            
            conversations.append(conversation)
    
    except Exception as e:
        logger.error(f"Error analyzing modern conversations: {e}")
        # Try a simplified query as fallback
        try:
            cursor.execute("SELECT * FROM chat")
            rows = cursor.fetchall()
            
            for row in rows:
                conversations.append(dict(row))
        except Exception as e2:
            logger.error(f"Error with fallback conversation query: {e2}")
    
    return conversations


def _analyze_modern_attachments(cursor: sqlite3.Cursor, limit: int) -> List[Dict]:
    """
    Analyze attachments in the modern schema (iOS 6+)
    
    Args:
        cursor: SQLite database cursor
        limit: Maximum number of attachments to analyze
        
    Returns:
        List of dictionaries with attachment information
    """
    attachments = []
    
    try:
        query = """
            SELECT
                a.ROWID as attachment_id,
                a.filename as filename,
                a.mime_type as mime_type,
                a.transfer_name as transfer_name,
                a.total_bytes as size,
                a.created_date as created_date,
                a.start_date as start_date,
                a.transfer_state as transfer_state,
                a.is_outgoing as is_outgoing,
                m.ROWID as message_id,
                m.text as message_text,
                m.date as message_date
            FROM
                attachment as a
            LEFT JOIN
                message_attachment_join as maj ON a.ROWID = maj.attachment_id
            LEFT JOIN
                message as m ON maj.message_id = m.ROWID
            ORDER BY
                a.created_date DESC
            LIMIT ?
        """
        
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        
        for row in rows:
            attachment = dict(row)
            
            # Convert timestamps
            for key in ['created_date', 'start_date', 'message_date']:
                if attachment.get(key):
                    mac_absolute_time = attachment[key]
                    if mac_absolute_time:
                        unix_timestamp = mac_absolute_time + 978307200  # Offset between epochs
                        attachment[f"{key}_formatted"] = datetime.fromtimestamp(unix_timestamp / 1e9).isoformat()
            
            # Make boolean values actual booleans
            for key in ['is_outgoing']:
                if key in attachment and attachment[key] is not None:
                    attachment[key] = bool(attachment[key])
            
            # Convert transfer state to human-readable value
            transfer_states = {
                0: 'Not Transferred',
                1: 'Transferring',
                2: 'Transferred',
                3: 'Failed',
                4: 'Cancelled'
            }
            
            if 'transfer_state' in attachment and attachment['transfer_state'] in transfer_states:
                attachment['transfer_state_text'] = transfer_states[attachment['transfer_state']]
            
            attachments.append(attachment)
    
    except Exception as e:
        logger.error(f"Error analyzing modern attachments: {e}")
        # Try a simplified query as fallback
        try:
            cursor.execute("SELECT * FROM attachment LIMIT ?", (limit,))
            rows = cursor.fetchall()
            
            for row in rows:
                attachments.append(dict(row))
        except Exception as e2:
            logger.error(f"Error with fallback attachment query: {e2}")
    
    return attachments


def _analyze_legacy_messages(cursor: sqlite3.Cursor, limit: int) -> List[Dict]:
    """
    Analyze messages in the legacy schema (iOS 5 and earlier)
    
    Args:
        cursor: SQLite database cursor
        limit: Maximum number of messages to analyze
        
    Returns:
        List of dictionaries with message information
    """
    messages = []
    
    try:
        query = """
            SELECT
                m.ROWID as message_id,
                m.address as contact_id,
                m.date as timestamp,
                m.text as body,
                m.flags as flags,
                m.service as service,
                m.group_id as group_id,
                m.subject as subject,
                m.madrid_flags as madrid_flags,
                m.madrid_error as madrid_error,
                m.read as is_read
            FROM
                messages as m
            ORDER BY
                m.date DESC
            LIMIT ?
        """
        
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        
        for row in rows:
            message = dict(row)
            
            # Convert timestamps
            if message.get('timestamp'):
                # iOS timestamps are in Mac Absolute Time (seconds since 2001-01-01)
                mac_absolute_time = message['timestamp']
                if mac_absolute_time:
                    unix_timestamp = mac_absolute_time + 978307200  # Offset between epochs
                    message['date'] = datetime.fromtimestamp(unix_timestamp).isoformat()
                    message['timestamp_unix'] = unix_timestamp
            
            # Determine message direction based on flags
            if 'flags' in message:
                # Bit 1 is set for outgoing messages
                message['is_from_me'] = bool(message['flags'] & 0x01)
            
            # Determine read status
            if 'is_read' in message:
                message['is_read'] = bool(message['is_read'])
            
            # Determine if delivered based on madrid_flags
            if 'madrid_flags' in message:
                # Bit 1 indicates delivered
                message['is_delivered'] = bool(message['madrid_flags'] & 0x01)
            
            messages.append(message)
    
    except Exception as e:
        logger.error(f"Error analyzing legacy messages: {e}")
        # Try a simplified query as fallback
        try:
            cursor.execute("SELECT * FROM messages ORDER BY date DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            
            for row in rows:
                messages.append(dict(row))
        except Exception as e2:
            logger.error(f"Error with fallback legacy message query: {e2}")
    
    return messages


def _infer_legacy_conversations(messages: List[Dict]) -> List[Dict]:
    """
    Infer conversations from legacy messages
    
    Args:
        messages: List of message dictionaries
        
    Returns:
        List of dictionaries with inferred conversation information
    """
    conversations = {}
    
    for message in messages:
        contact_id = message.get('contact_id')
        if not contact_id:
            continue
        
        if contact_id not in conversations:
            conversations[contact_id] = {
                'conversation_id': f"inferred_{len(conversations) + 1}",
                'identifier': contact_id,
                'service': message.get('service', 'unknown'),
                'message_count': 0,
                'participants': [{
                    'identifier': contact_id,
                    'service': message.get('service', 'unknown')
                }]
            }
        
        conversations[contact_id]['message_count'] += 1
    
    return list(conversations.values())


def _analyze_legacy_attachments(cursor: sqlite3.Cursor, limit: int) -> List[Dict]:
    """
    Analyze attachments in the legacy schema (iOS 5 and earlier)
    
    Args:
        cursor: SQLite database cursor
        limit: Maximum number of attachments to analyze
        
    Returns:
        List of dictionaries with attachment information
    """
    attachments = []
    
    try:
        # Check if msg_pieces table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='msg_pieces'")
        has_msg_pieces = cursor.fetchone() is not None
        
        if has_msg_pieces:
            query = """
                SELECT
                    p.ROWID as attachment_id,
                    p.content_loc as filename,
                    p.content_type as mime_type,
                    p.data as data,
                    p.flags as flags,
                    m.ROWID as message_id,
                    m.text as message_text,
                    m.date as message_date
                FROM
                    msg_pieces as p
                JOIN
                    messages as m ON p.message_id = m.ROWID
                LIMIT ?
            """
            
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            
            for row in rows:
                attachment = dict(row)
                
                # Convert timestamps
                if attachment.get('message_date'):
                    mac_absolute_time = attachment['message_date']
                    if mac_absolute_time:
                        unix_timestamp = mac_absolute_time + 978307200  # Offset between epochs
                        attachment['message_date_formatted'] = datetime.fromtimestamp(unix_timestamp).isoformat()
                
                # Replace binary data with length information
                if 'data' in attachment and attachment['data'] is not None:
                    data_length = len(attachment['data']) if isinstance(attachment['data'], bytes) else 0
                    attachment['data'] = f"<binary data: {data_length} bytes>"
                
                attachments.append(attachment)
        else:
            # If msg_pieces doesn't exist, try to find attachments mentioned in message text
            # This is a very limited fallback
            cursor.execute("""
                SELECT
                    ROWID as message_id,
                    text as message_text,
                    date as message_date
                FROM
                    messages
                WHERE
                    text LIKE '%<Attachment:%'
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            
            for row in rows:
                message = dict(row)
                
                # Extract attachment references from text
                text = message.get('message_text', '')
                if isinstance(text, bytes):
                    try:
                        text = text.decode('utf-8', errors='replace')
                    except Exception:
                        text = str(text)
                
                import re
                attachment_refs = re.findall(r'<Attachment:([^>]+)>', text)
                
                for ref in attachment_refs:
                    attachment = {
                        'message_id': message['message_id'],
                        'reference': ref,
                        'inferred': True,
                        'message_date': message.get('message_date')
                    }
                    
                    # Convert timestamp
                    if attachment.get('message_date'):
                        mac_absolute_time = attachment['message_date']
                        if mac_absolute_time:
                            unix_timestamp = mac_absolute_time + 978307200  # Offset between epochs
                            attachment['message_date_formatted'] = datetime.fromtimestamp(unix_timestamp).isoformat()
                    
                    attachments.append(attachment)
    
    except Exception as e:
        logger.error(f"Error analyzing legacy attachments: {e}")
    
    return attachments


def extract_message_statistics(db_path: str) -> Dict:
    """
    Extract message statistics from SMS/iMessage database
    
    Args:
        db_path: Path to the message database
        
    Returns:
        Dictionary with message statistics
    """
    logger.info(f"Extracting message statistics from {db_path}")
    
    analysis = analyze_messages(db_path, limit=0)  # Just metadata, no message content
    
    # Extract statistics
    return analysis.get('statistics', {})


def search_messages(db_path: str, query: str, case_sensitive: bool = False, limit: int = 100) -> Dict:
    """
    Search for messages containing specific text
    
    Args:
        db_path: Path to the message database
        query: Search query
        case_sensitive: Whether to perform case-sensitive search
        limit: Maximum number of results to return
        
    Returns:
        Dictionary with search results
    """
    logger.info(f"Searching messages in {db_path} for '{query}'")
    
    if not is_sqlite_database(db_path):
        raise ValueError(f"Not a valid SQLite database: {db_path}")
    
    try:
        # Create a temporary copy of the database for forensic integrity
        temp_dir = tempfile.mkdtemp()
        temp_db_path = os.path.join(temp_dir, os.path.basename(db_path))
        
        # Copy the database file
        shutil.copy2(db_path, temp_db_path)
        
        # Check for and handle WAL and SHM files
        wal_path = f"{db_path}-wal"
        shm_path = f"{db_path}-shm"
        
        has_wal = os.path.exists(wal_path)
        has_shm = os.path.exists(shm_path)
        
        if has_wal:
            temp_wal_path = f"{temp_db_path}-wal"
            shutil.copy2(wal_path, temp_wal_path)
            logger.info(f"Found and copied WAL file: {wal_path}")
        
        if has_shm:
            temp_shm_path = f"{temp_db_path}-shm"
            shutil.copy2(shm_path, temp_shm_path)
            logger.info(f"Found and copied SHM file: {shm_path}")
        
        # Open the temporary copy with SQLITE_OPEN_READONLY flag
        uri = f"file:{temp_db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        
        # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
        conn.execute("PRAGMA journal_mode=OFF")
        
        # Disable WAL mode to prevent modification
        conn.execute("PRAGMA locking_mode=NORMAL")
        
        cursor = conn.cursor()
        
        # Determine database schema version
        db_version = _determine_message_db_version(cursor)
        
        # Build the search query based on schema version
        if db_version == 'modern':  # iOS 6+ schema
            # Check if the handle table exists (iOS 9+)
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='handle'")
            has_handle_table = cursor.fetchone() is not None
            
            if has_handle_table:
                # Modern schema with handle table (iOS 9+)
                if case_sensitive:
                    sql_query = """
                        SELECT
                            m.ROWID as message_id,
                            m.date as timestamp,
                            h.id as contact_id,
                            m.text as body,
                            m.service as service,
                            m.is_from_me as is_from_me,
                            c.chat_identifier as conversation_id
                        FROM
                            message as m
                        LEFT JOIN
                            handle as h ON m.handle_id = h.ROWID
                        LEFT JOIN
                            chat_message_join as cmj ON m.ROWID = cmj.message_id
                        LEFT JOIN
                            chat as c ON cmj.chat_id = c.ROWID
                        WHERE
                            m.text LIKE ?
                        ORDER BY
                            m.date DESC
                        LIMIT ?
                    """
                else:
                    sql_query = """
                        SELECT
                            m.ROWID as message_id,
                            m.date as timestamp,
                            h.id as contact_id,
                            m.text as body,
                            m.service as service,
                            m.is_from_me as is_from_me,
                            c.chat_identifier as conversation_id
                        FROM
                            message as m
                        LEFT JOIN
                            handle as h ON m.handle_id = h.ROWID
                        LEFT JOIN
                            chat_message_join as cmj ON m.ROWID = cmj.message_id
                        LEFT JOIN
                            chat as c ON cmj.chat_id = c.ROWID
                        WHERE
                            LOWER(m.text) LIKE LOWER(?)
                        ORDER BY
                            m.date DESC
                        LIMIT ?
                    """
            else:
                # Modern schema without handle table (iOS 6-8)
                if case_sensitive:
                    sql_query = """
                        SELECT
                            m.ROWID as message_id,
                            m.date as timestamp,
                            m.address as contact_id,
                            m.text as body,
                            m.service as service,
                            m.is_from_me as is_from_me,
                            c.chat_identifier as conversation_id
                        FROM
                            message as m
                        LEFT JOIN
                            chat_message_join as cmj ON m.ROWID = cmj.message_id
                        LEFT JOIN
                            chat as c ON cmj.chat_id = c.ROWID
                        WHERE
                            m.text LIKE ?
                        ORDER BY
                            m.date DESC
                        LIMIT ?
                    """
                else:
                    sql_query = """
                        SELECT
                            m.ROWID as message_id,
                            m.date as timestamp,
                            m.address as contact_id,
                            m.text as body,
                            m.service as service,
                            m.is_from_me as is_from_me,
                            c.chat_identifier as conversation_id
                        FROM
                            message as m
                        LEFT JOIN
                            chat_message_join as cmj ON m.ROWID = cmj.message_id
                        LEFT JOIN
                            chat as c ON cmj.chat_id = c.ROWID
                        WHERE
                            LOWER(m.text) LIKE LOWER(?)
                        ORDER BY
                            m.date DESC
                        LIMIT ?
                    """
        elif db_version == 'legacy':  # iOS 5 and earlier
            if case_sensitive:
                sql_query = """
                    SELECT
                        m.ROWID as message_id,
                        m.address as contact_id,
                        m.date as timestamp,
                        m.text as body,
                        m.service as service,
                        m.flags as flags,
                        m.group_id as group_id
                    FROM
                        messages as m
                    WHERE
                        m.text LIKE ?
                    ORDER BY
                        m.date DESC
                    LIMIT ?
                """
            else:
                sql_query = """
                    SELECT
                        m.ROWID as message_id,
                        m.address as contact_id,
                        m.date as timestamp,
                        m.text as body,
                        m.service as service,
                        m.flags as flags,
                        m.group_id as group_id
                    FROM
                        messages as m
                    WHERE
                        LOWER(m.text) LIKE LOWER(?)
                    ORDER BY
                        m.date DESC
                    LIMIT ?
                """
        else:
            # Generic fallback query
            if case_sensitive:
                sql_query = """
                    SELECT *
                    FROM message
                    WHERE text LIKE ?
                    LIMIT ?
                """
            else:
                sql_query = """
                    SELECT *
                    FROM message
                    WHERE LOWER(text) LIKE LOWER(?)
                    LIMIT ?
                """
        
        # Execute the search query
        search_pattern = f'%{query}%'
        cursor.execute(sql_query, (search_pattern, limit))
        rows = cursor.fetchall()
        
        # Process results
        search_results = []
        for row in rows:
            message = dict(row)
            
            # Convert timestamps
            if message.get('timestamp'):
                # iOS timestamps are in Mac Absolute Time (seconds since 2001-01-01)
                mac_absolute_time = message['timestamp']
                if mac_absolute_time:
                    unix_timestamp = mac_absolute_time + 978307200  # Offset between epochs
                    message['date'] = datetime.fromtimestamp(unix_timestamp / 1e9).isoformat()
                    message['timestamp_unix'] = unix_timestamp
            
            # Make boolean values actual booleans
            for key in ['is_from_me']:
                if key in message and message[key] is not None:
                    message[key] = bool(message[key])
            
            # For legacy schema, determine message direction based on flags
            if db_version == 'legacy' and 'flags' in message:
                # Bit 1 is set for outgoing messages
                message['is_from_me'] = bool(message['flags'] & 0x01)
            
            # Highlight the matching text
            if 'body' in message and message['body']:
                text_body = message['body']
                if isinstance(text_body, bytes):
                    try:
                        text_body = text_body.decode('utf-8', errors='replace')
                    except Exception:
                        text_body = str(text_body)
                
                # Create a highlighted version
                try:
                    if case_sensitive:
                        message['body_highlighted'] = text_body.replace(
                            query, f"****{query}****"
                        )
                    else:
                        # Case-insensitive replacement is more complex
                        import re
                        pattern = re.compile(re.escape(query), re.IGNORECASE)
                        message['body_highlighted'] = pattern.sub(
                            lambda m: f"****{m.group(0)}****", text_body
                        )
                except Exception as e:
                    logger.warning(f"Error highlighting text: {e}")
                    message['body_highlighted'] = text_body
            
            search_results.append(message)
        
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
        
        # Return the search results
        return {
            'db_path': db_path,
            'query': query,
            'case_sensitive': case_sensitive,
            'result_count': len(search_results),
            'has_more': len(search_results) >= limit,
            'results': search_results,
            'has_wal': has_wal,
            'has_shm': has_shm,
            'db_version': db_version
        }
    
    except Exception as e:
        logger.error(f"Error searching messages in {db_path}: {e}")
        raise