# tools/specialized/applications.py - iOS application analysis tools

import os
import plistlib
import sqlite3
import logging
import tempfile
import shutil
import json
import re
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)

# Import tools
from tools.sqlite.analyzer import is_sqlite_database, execute_query
from tools.plist.parser import parse_plist, is_plist_file
from utils.path_utils import find_files_by_extension


class AppAnalyzer:
    """
    Analyzer for iOS application data
    
    Extracts and analyzes data from installed iOS applications
    """
    
    def __init__(self, ios_root: str):
        """
        Initialize the application analyzer
        
        Args:
            ios_root: iOS file system root directory
        """
        self.ios_root = ios_root
        
        # Known app container paths
        self.app_locations = {
            'bundle': os.path.join(ios_root, 'private/var/containers/Bundle/Application'),
            'data': os.path.join(ios_root, 'private/var/mobile/Containers/Data/Application'),
            'shared': os.path.join(ios_root, 'private/var/mobile/Containers/Shared/AppGroup'),
            'plugins': os.path.join(ios_root, 'private/var/mobile/Containers/PluginKitPlugin'),
            # Legacy paths (iOS 7 and earlier)
            'legacy_apps': os.path.join(ios_root, 'private/var/mobile/Applications'),
            # User app data
            'user_data': os.path.join(ios_root, 'private/var/mobile/Library/Mobile Documents')
        }
    
    def find_installed_apps(self) -> List[Dict[str, Any]]:
        """
        Find installed applications on the iOS device
        
        Returns:
            List of dictionaries with app information
        """
        logger.info(f"Finding installed applications in {self.ios_root}")
        
        apps = []
        
        # Check bundle container
        bundle_path = self.app_locations['bundle']
        if os.path.exists(bundle_path) and os.path.isdir(bundle_path):
            # Modern iOS app structure (iOS 8+)
            for uuid_dir in os.listdir(bundle_path):
                uuid_path = os.path.join(bundle_path, uuid_dir)
                if os.path.isdir(uuid_path):
                    # Look for .app directories
                    for item in os.listdir(uuid_path):
                        if item.endswith('.app') and os.path.isdir(os.path.join(uuid_path, item)):
                            app_path = os.path.join(uuid_path, item)
                            app_info = self._extract_app_info(app_path, uuid_dir)
                            if app_info:
                                apps.append(app_info)
        
        # Check legacy app path
        legacy_path = self.app_locations['legacy_apps']
        if os.path.exists(legacy_path) and os.path.isdir(legacy_path):
            # iOS 7 and earlier app structure
            for uuid_dir in os.listdir(legacy_path):
                uuid_path = os.path.join(legacy_path, uuid_dir)
                if os.path.isdir(uuid_path):
                    # Look for .app directories
                    for item in os.listdir(uuid_path):
                        if item.endswith('.app') and os.path.isdir(os.path.join(uuid_path, item)):
                            app_path = os.path.join(uuid_path, item)
                            app_info = self._extract_app_info(app_path, uuid_dir, legacy=True)
                            if app_info:
                                apps.append(app_info)
        
        logger.info(f"Found {len(apps)} installed applications")
        return apps
    
    def _extract_app_info(self, app_path: str, uuid: str, legacy: bool = False) -> Optional[Dict[str, Any]]:
        """
        Extract information from an application bundle
        
        Args:
            app_path: Path to the .app directory
            uuid: UUID of the app container
            legacy: Whether this is a legacy app structure
            
        Returns:
            Dictionary with app information or None if extraction fails
        """
        try:
            # Check for Info.plist
            info_plist_path = os.path.join(app_path, 'Info.plist')
            if not os.path.exists(info_plist_path):
                return None
            
            # Parse Info.plist
            info_plist = parse_plist(info_plist_path)
            
            # Extract key information
            bundle_id = info_plist.get('CFBundleIdentifier', 'unknown')
            display_name = info_plist.get('CFBundleDisplayName', info_plist.get('CFBundleName', 'Unknown App'))
            version = info_plist.get('CFBundleShortVersionString', 'unknown')
            build = info_plist.get('CFBundleVersion', 'unknown')
            
            # Find app data container
            data_container = None
            if not legacy:
                data_path = self.app_locations['data']
                if os.path.exists(data_path) and os.path.isdir(data_path):
                    # Search for matching container
                    for data_uuid in os.listdir(data_path):
                        data_uuid_path = os.path.join(data_path, data_uuid)
                        if os.path.isdir(data_uuid_path):
                            # Check .com.apple.mobile_container_manager.metadata.plist
                            metadata_path = os.path.join(data_uuid_path, '.com.apple.mobile_container_manager.metadata.plist')
                            if os.path.exists(metadata_path):
                                try:
                                    metadata = parse_plist(metadata_path)
                                    if metadata.get('MCMMetadataIdentifier') == bundle_id:
                                        data_container = data_uuid_path
                                        break
                                except Exception as e:
                                    logger.warning(f"Error parsing metadata plist for {data_uuid_path}: {e}")
            else:
                # Legacy structure has data in the same container
                data_container = os.path.dirname(app_path)
            
            # Find shared app group containers
            shared_containers = []
            shared_path = self.app_locations['shared']
            if os.path.exists(shared_path) and os.path.isdir(shared_path):
                for shared_uuid in os.listdir(shared_path):
                    shared_uuid_path = os.path.join(shared_path, shared_uuid)
                    if os.path.isdir(shared_uuid_path):
                        # Check metadata plist
                        metadata_path = os.path.join(shared_uuid_path, '.com.apple.mobile_container_manager.metadata.plist')
                        if os.path.exists(metadata_path):
                            try:
                                metadata = parse_plist(metadata_path)
                                # Check if this app is a member of the group
                                if metadata.get('MCMMetadataIdentifier', '').startswith('group.'):
                                    # This is a shared app group, check if our app is a member
                                    entitlements_path = os.path.join(app_path, 'archived-expanded-entitlements.xcent')
                                    if os.path.exists(entitlements_path):
                                        try:
                                            entitlements = parse_plist(entitlements_path)
                                            app_groups = entitlements.get('com.apple.security.application-groups', [])
                                            if metadata.get('MCMMetadataIdentifier') in app_groups:
                                                shared_containers.append({
                                                    'group_id': metadata.get('MCMMetadataIdentifier'),
                                                    'path': shared_uuid_path,
                                                    'uuid': shared_uuid
                                                })
                                        except Exception as e:
                                            logger.warning(f"Error parsing entitlements for {app_path}: {e}")
                            except Exception as e:
                                logger.warning(f"Error parsing metadata plist for {shared_uuid_path}: {e}")
            
            # Collect app metadata
            app_info = {
                'bundle_id': bundle_id,
                'display_name': display_name,
                'version': version,
                'build': build,
                'bundle_path': app_path,
                'bundle_uuid': uuid,
                'data_container': data_container,
                'data_uuid': os.path.basename(data_container) if data_container else None,
                'shared_containers': shared_containers,
                'info_plist': info_plist,
                'legacy': legacy
            }
            
            # Additional metadata
            app_info['executable'] = info_plist.get('CFBundleExecutable')
            app_info['minimum_os_version'] = info_plist.get('MinimumOSVersion')
            app_info['device_family'] = info_plist.get('UIDeviceFamily')
            app_info['supported_interfaces'] = info_plist.get('UISupportedInterfaceOrientations')
            
            # Get app icon if available
            icon_name = info_plist.get('CFBundleIconFile')
            if icon_name:
                if not icon_name.endswith('.png'):
                    icon_name += '.png'
                icon_path = os.path.join(app_path, icon_name)
                if os.path.exists(icon_path):
                    app_info['icon_path'] = icon_path
            
            # Check for alternative icon paths
            icon_files = info_plist.get('CFBundleIconFiles', [])
            if icon_files and isinstance(icon_files, list) and not app_info.get('icon_path'):
                for icon_file in icon_files:
                    if not icon_file.endswith('.png'):
                        icon_file += '.png'
                    icon_path = os.path.join(app_path, icon_file)
                    if os.path.exists(icon_path):
                        app_info['icon_path'] = icon_path
                        break
            
            return app_info
        
        except Exception as e:
            logger.error(f"Error extracting app info from {app_path}: {e}")
            return None
    
    def analyze_app_data(self, app_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze application data directory for forensic artifacts
        
        Args:
            app_info: App information dictionary
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing app data for {app_info.get('display_name')} ({app_info.get('bundle_id')})")
        
        data_container = app_info.get('data_container')
        if not data_container or not os.path.exists(data_container):
            return {
                'bundle_id': app_info.get('bundle_id'),
                'display_name': app_info.get('display_name'),
                'error': 'Data container not found'
            }
        
        analysis = {
            'bundle_id': app_info.get('bundle_id'),
            'display_name': app_info.get('display_name'),
            'version': app_info.get('version'),
            'databases': [],
            'plists': [],
            'caches': [],
            'documents': [],
            'shared_data': []
        }
        
        # Analyze databases
        db_paths = find_files_by_extension(data_container, ['db', 'sqlite', 'sqlitedb', 'sqlite3'])
        for db_path in db_paths:
            if is_sqlite_database(db_path):
                rel_path = os.path.relpath(db_path, data_container)
                db_info = {
                    'path': db_path,
                    'relative_path': rel_path,
                    'size': os.path.getsize(db_path),
                    'name': os.path.basename(db_path)
                }
                
                # Check if there's a WAL file
                wal_path = f"{db_path}-wal"
                if os.path.exists(wal_path):
                    db_info['has_wal'] = True
                    db_info['wal_size'] = os.path.getsize(wal_path)
                else:
                    db_info['has_wal'] = False
                
                # Try to get table info
                try:
                    # Create a temporary copy to prevent modification
                    temp_dir = tempfile.mkdtemp()
                    temp_db_path = os.path.join(temp_dir, os.path.basename(db_path))
                    
                    # Copy the database
                    shutil.copy2(db_path, temp_db_path)
                    
                    # Handle WAL if it exists
                    if db_info['has_wal']:
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
                    
                    # Get table list
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in cursor.fetchall()]
                    db_info['tables'] = tables
                    
                    # Try to determine the purpose of this database
                    purpose = self._guess_database_purpose(db_path, tables)
                    if purpose:
                        db_info['purpose'] = purpose
                    
                    conn.close()
                    
                    # Clean up temporary files
                    os.remove(temp_db_path)
                    if os.path.exists(f"{temp_db_path}-wal"):
                        os.remove(f"{temp_db_path}-wal")
                    os.rmdir(temp_dir)
                except Exception as e:
                    logger.warning(f"Error analyzing database {db_path}: {e}")
                
                analysis['databases'].append(db_info)
        
        # Analyze plists
        plist_paths = find_files_by_extension(data_container, ['plist'])
        for plist_path in plist_paths:
            if is_plist_file(plist_path):
                rel_path = os.path.relpath(plist_path, data_container)
                plist_info = {
                    'path': plist_path,
                    'relative_path': rel_path,
                    'size': os.path.getsize(plist_path),
                    'name': os.path.basename(plist_path)
                }
                
                # Try to determine the purpose of this plist
                purpose = self._guess_plist_purpose(plist_path)
                if purpose:
                    plist_info['purpose'] = purpose
                
                analysis['plists'].append(plist_info)
        
        # Check for common app directories
        directories_to_check = {
            'Documents': 'documents',
            'Library/Caches': 'caches',
            'Library/Preferences': 'preferences',
            'tmp': 'temporary'
        }
        
        for dir_name, category in directories_to_check.items():
            dir_path = os.path.join(data_container, dir_name)
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                # Add basic information about this directory
                if category not in analysis:
                    analysis[category] = []
                
                analysis[category].append({
                    'path': dir_path,
                    'size': self._get_dir_size(dir_path),
                    'file_count': len(os.listdir(dir_path))
                })
        
        # Analyze shared containers
        for shared_container in app_info.get('shared_containers', []):
            container_path = shared_container.get('path')
            if container_path and os.path.exists(container_path):
                shared_info = {
                    'group_id': shared_container.get('group_id'),
                    'path': container_path,
                    'databases': [],
                    'plists': []
                }
                
                # Look for databases in shared container
                shared_dbs = find_files_by_extension(container_path, ['db', 'sqlite', 'sqlitedb', 'sqlite3'])
                for db_path in shared_dbs:
                    if is_sqlite_database(db_path):
                        rel_path = os.path.relpath(db_path, container_path)
                        db_info = {
                            'path': db_path,
                            'relative_path': rel_path,
                            'size': os.path.getsize(db_path),
                            'name': os.path.basename(db_path)
                        }
                        shared_info['databases'].append(db_info)
                
                # Look for plists in shared container
                shared_plists = find_files_by_extension(container_path, ['plist'])
                for plist_path in shared_plists:
                    if is_plist_file(plist_path):
                        rel_path = os.path.relpath(plist_path, container_path)
                        plist_info = {
                            'path': plist_path,
                            'relative_path': rel_path,
                            'size': os.path.getsize(plist_path),
                            'name': os.path.basename(plist_path)
                        }
                        shared_info['plists'].append(plist_info)
                
                analysis['shared_data'].append(shared_info)
        
        return analysis
    
    def _get_dir_size(self, dir_path: str) -> int:
        """
        Get the total size of a directory
        
        Args:
            dir_path: Path to the directory
            
        Returns:
            Total size in bytes
        """
        total_size = 0
        for dirpath, _, filenames in os.walk(dir_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    total_size += os.path.getsize(file_path)
        return total_size
    
    def _guess_database_purpose(self, db_path: str, tables: List[str]) -> Optional[str]:
        """
        Try to guess the purpose of a database based on path and tables
        
        Args:
            db_path: Path to the database
            tables: List of table names
            
        Returns:
            Purpose string or None if unknown
        """
        db_name = os.path.basename(db_path).lower()
        
        # Messages or chat database
        if db_name in ['messages.sqlite', 'chat.db', 'sms.db'] or any(t.lower() in ['messages', 'chat', 'conversation'] for t in tables):
            return 'Messages/Chat'
        
        # Contacts database
        if db_name in ['contacts.sqlite', 'addressbook.sqlitedb'] or any(t.lower() in ['contacts', 'people', 'person'] for t in tables):
            return 'Contacts'
        
        # Calendar database
        if db_name in ['calendar.sqlite', 'calendar.sqlitedb'] or any(t.lower() in ['calendar', 'event', 'reminder'] for t in tables):
            return 'Calendar/Events'
        
        # Notes database
        if db_name in ['notes.sqlite', 'notesstore.sqlite'] or any(t.lower() in ['notes', 'note', 'notedata'] for t in tables):
            return 'Notes'
        
        # Browser database
        if db_name in ['history.sqlite', 'cookies.sqlite', 'browser.db'] or any(t.lower() in ['history', 'visits', 'cookies'] for t in tables):
            return 'Browser History/Cookies'
        
        # Location database
        if db_name in ['locations.sqlite', 'position.db'] or any(t.lower() in ['location', 'position', 'place'] for t in tables):
            return 'Location'
        
        # Cache database
        if 'cache' in db_name or any(t.lower().startswith('cache') for t in tables):
            return 'Cache'
        
        # Settings/preferences database
        if 'settings' in db_name or 'preferences' in db_name or any(t.lower() in ['settings', 'preferences', 'config'] for t in tables):
            return 'Settings/Preferences'
        
        # Media database
        if any(db_name.startswith(prefix) for prefix in ['media', 'photo', 'image', 'video']) or any(t.lower() in ['media', 'photo', 'image', 'video'] for t in tables):
            return 'Media'
        
        return None
    
    def _guess_plist_purpose(self, plist_path: str) -> Optional[str]:
        """
        Try to guess the purpose of a plist based on path and name
        
        Args:
            plist_path: Path to the plist
            
        Returns:
            Purpose string or None if unknown
        """
        plist_name = os.path.basename(plist_path).lower()
        
        # App preferences
        if plist_name.endswith('preferences.plist') or 'preferences' in plist_path:
            return 'App Preferences'
        
        # Settings
        if 'settings' in plist_name:
            return 'Settings'
        
        # Cache information
        if 'cache' in plist_name:
            return 'Cache Information'
        
        # Login/authentication
        if any(term in plist_name for term in ['login', 'auth', 'credential', 'token']):
            return 'Authentication/Credentials'
        
        # State information
        if 'state' in plist_name:
            return 'State Information'
        
        # User data
        if 'user' in plist_name:
            return 'User Data'
        
        return None
    
    def extract_app_user_data(self, app_info: Dict[str, Any], data_category: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract app user data for a specific category
        
        Args:
            app_info: App information dictionary
            data_category: Optional data category to focus on
                          (e.g., 'messages', 'contacts', 'location')
            
        Returns:
            Dictionary with extracted user data
        """
        logger.info(f"Extracting user data for {app_info.get('display_name')} ({app_info.get('bundle_id')})")
        
        data_container = app_info.get('data_container')
        if not data_container or not os.path.exists(data_container):
            return {
                'bundle_id': app_info.get('bundle_id'),
                'display_name': app_info.get('display_name'),
                'error': 'Data container not found'
            }
        
        extraction_result = {
            'bundle_id': app_info.get('bundle_id'),
            'display_name': app_info.get('display_name'),
            'category': data_category,
            'data': []
        }
        
        # Analyze app data first
        app_analysis = self.analyze_app_data(app_info)
        
        # Extract data based on category
        if data_category == 'messages' or data_category is None:
            # Look for message databases
            for db_info in app_analysis.get('databases', []):
                if db_info.get('purpose') == 'Messages/Chat':
                    messages = self._extract_messages_from_db(db_info.get('path'))
                    if messages:
                        extraction_result['data'].append({
                            'type': 'messages',
                            'source': db_info.get('name'),
                            'count': len(messages),
                            'messages': messages
                        })
        
        if data_category == 'contacts' or data_category is None:
            # Look for contact databases
            for db_info in app_analysis.get('databases', []):
                if db_info.get('purpose') == 'Contacts':
                    contacts = self._extract_contacts_from_db(db_info.get('path'))
                    if contacts:
                        extraction_result['data'].append({
                            'type': 'contacts',
                            'source': db_info.get('name'),
                            'count': len(contacts),
                            'contacts': contacts
                        })
        
        if data_category == 'location' or data_category is None:
            # Look for location databases
            for db_info in app_analysis.get('databases', []):
                if db_info.get('purpose') == 'Location':
                    locations = self._extract_locations_from_db(db_info.get('path'))
                    if locations:
                        extraction_result['data'].append({
                            'type': 'locations',
                            'source': db_info.get('name'),
                            'count': len(locations),
                            'locations': locations
                        })
        
        if data_category == 'media' or data_category is None:
            # Look for media files in Documents directory
            documents_dir = os.path.join(data_container, 'Documents')
            if os.path.exists(documents_dir) and os.path.isdir(documents_dir):
                media_files = []
                for ext in ['jpg', 'jpeg', 'png', 'gif', 'mp4', 'mov', 'mp3', 'm4a']:
                    media_files.extend(find_files_by_extension(documents_dir, [ext]))
                
                if media_files:
                    extraction_result['data'].append({
                        'type': 'media',
                        'source': 'Documents',
                        'count': len(media_files),
                        'files': [{'path': f, 'size': os.path.getsize(f), 'name': os.path.basename(f)} for f in media_files]
                    })
        
        if data_category == 'preferences' or data_category is None:
            # Extract app preferences
            prefs = {}
            prefs_dir = os.path.join(data_container, 'Library/Preferences')
            if os.path.exists(prefs_dir) and os.path.isdir(prefs_dir):
                plist_files = find_files_by_extension(prefs_dir, ['plist'])
                for plist_path in plist_files:
                    try:
                        plist_data = parse_plist(plist_path)
                        prefs[os.path.basename(plist_path)] = plist_data
                    except Exception as e:
                        logger.warning(f"Error parsing plist {plist_path}: {e}")
            
            if prefs:
                extraction_result['data'].append({
                    'type': 'preferences',
                    'source': 'Library/Preferences',
                    'count': len(prefs),
                    'preferences': prefs
                })
        
        return extraction_result
    
    def _extract_messages_from_db(self, db_path: str) -> List[Dict[str, Any]]:
        """
        Extract messages from a database
        
        Args:
            db_path: Path to the database
            
        Returns:
            List of message dictionaries
        """
        messages = []
        
        try:
            # Create a temporary copy to prevent modification
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, os.path.basename(db_path))
            
            # Copy the database
            shutil.copy2(db_path, temp_db_path)
            
            # Check for WAL file
            wal_path = f"{db_path}-wal"
            if os.path.exists(wal_path):
                temp_wal_path = f"{temp_db_path}-wal"
                shutil.copy2(wal_path, temp_wal_path)
            
            # Open with URI for read-only access
            uri = f"file:{temp_db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            
            # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
            conn.execute("PRAGMA journal_mode=OFF")
            
            # Disable WAL mode to prevent modification
            conn.execute("PRAGMA locking_mode=NORMAL")
            
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Look for message tables
            message_tables = []
            for table in tables:
                # Check if this looks like a message table
                try:
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row[1] for row in cursor.fetchall()]
                    
                    # Check for message-like columns
                    message_columns = ['text', 'body', 'content', 'message']
                    time_columns = ['date', 'time', 'timestamp']
                    sender_columns = ['sender', 'from', 'author']
                    
                    has_message = any(col for col in columns if any(mcol in col.lower() for mcol in message_columns))
                    has_time = any(col for col in columns if any(tcol in col.lower() for tcol in time_columns))
                    
                    if has_message and has_time:
                        message_tables.append({
                            'name': table,
                            'columns': columns
                        })
                except Exception as e:
                    logger.warning(f"Error checking table {table} in {db_path}: {e}")
            
            # Extract messages from each table
            for table_info in message_tables:
                table = table_info['name']
                columns = table_info['columns']
                
                # Identify key columns
                message_col = next((col for col in columns if any(mcol in col.lower() for mcol in ['text', 'body', 'content', 'message'])), None)
                time_col = next((col for col in columns if any(tcol in col.lower() for tcol in ['date', 'time', 'timestamp'])), None)
                sender_col = next((col for col in columns if any(scol in col.lower() for scol in ['sender', 'from', 'author'])), None)
                
                if message_col and time_col:
                    # Build query
                    query = f"SELECT * FROM {table} LIMIT 1000"
                    
                    try:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                        
                        for row in rows:
                            message = dict(row)
                            
                            # Add message to list
                            messages.append(message)
                    except Exception as e:
                        logger.warning(f"Error extracting messages from {table} in {db_path}: {e}")
            
            conn.close()
            
            # Clean up temporary files
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            os.rmdir(temp_dir)
        
        except Exception as e:
            logger.error(f"Error extracting messages from {db_path}: {e}")
        
        return messages
    
    def _extract_contacts_from_db(self, db_path: str) -> List[Dict[str, Any]]:
        """
        Extract contacts from a database
        
        Args:
            db_path: Path to the database
            
        Returns:
            List of contact dictionaries
        """
        contacts = []
        
        try:
            # Create a temporary copy to prevent modification
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, os.path.basename(db_path))
            
            # Copy the database
            shutil.copy2(db_path, temp_db_path)
            
            # Check for WAL file
            wal_path = f"{db_path}-wal"
            if os.path.exists(wal_path):
                temp_wal_path = f"{temp_db_path}-wal"
                shutil.copy2(wal_path, temp_wal_path)
            
            # Open with URI for read-only access
            uri = f"file:{temp_db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            
            # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
            conn.execute("PRAGMA journal_mode=OFF")
            
            # Disable WAL mode to prevent modification
            conn.execute("PRAGMA locking_mode=NORMAL")
            
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Look for contact tables
            contact_tables = []
            for table in tables:
                # Check if this looks like a contact table
                try:
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row[1] for row in cursor.fetchall()]
                    
                    # Check for contact-like columns
                    name_columns = ['name', 'first', 'last', 'display']
                    contact_columns = ['phone', 'email', 'address']
                    
                    has_name = any(col for col in columns if any(ncol in col.lower() for ncol in name_columns))
                    has_contact = any(col for col in columns if any(ccol in col.lower() for ccol in contact_columns))
                    
                    if has_name or has_contact:
                        contact_tables.append({
                            'name': table,
                            'columns': columns
                        })
                except Exception as e:
                    logger.warning(f"Error checking table {table} in {db_path}: {e}")
            
            # Extract contacts from each table
            for table_info in contact_tables:
                table = table_info['name']
                columns = table_info['columns']
                
                # Build query
                query = f"SELECT * FROM {table} LIMIT 1000"
                
                try:
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        contact = dict(row)
                        
                        # Add contact to list
                        contacts.append(contact)
                except Exception as e:
                    logger.warning(f"Error extracting contacts from {table} in {db_path}: {e}")
            
            conn.close()
            
            # Clean up temporary files
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            os.rmdir(temp_dir)
        
        except Exception as e:
            logger.error(f"Error extracting contacts from {db_path}: {e}")
        
        return contacts
    
    def _extract_locations_from_db(self, db_path: str) -> List[Dict[str, Any]]:
        """
        Extract location data from a database
        
        Args:
            db_path: Path to the database
            
        Returns:
            List of location dictionaries
        """
        locations = []
        
        try:
            # Create a temporary copy to prevent modification
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, os.path.basename(db_path))
            
            # Copy the database
            shutil.copy2(db_path, temp_db_path)
            
            # Check for WAL file
            wal_path = f"{db_path}-wal"
            if os.path.exists(wal_path):
                temp_wal_path = f"{temp_db_path}-wal"
                shutil.copy2(wal_path, temp_wal_path)
            
            # Open with URI for read-only access
            uri = f"file:{temp_db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            
            # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
            conn.execute("PRAGMA journal_mode=OFF")
            
            # Disable WAL mode to prevent modification
            conn.execute("PRAGMA locking_mode=NORMAL")
            
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Look for location tables
            location_tables = []
            for table in tables:
                # Check if this looks like a location table
                try:
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row[1] for row in cursor.fetchall()]
                    
                    # Check for location-like columns
                    coord_columns = ['latitude', 'longitude', 'lat', 'lon', 'coord']
                    location_columns = ['location', 'place', 'position']
                    time_columns = ['date', 'time', 'timestamp']
                    
                    has_coords = any(col for col in columns if any(ccol in col.lower() for ccol in coord_columns))
                    has_location = any(col for col in columns if any(lcol in col.lower() for lcol in location_columns))
                    
                    if has_coords or has_location:
                        location_tables.append({
                            'name': table,
                            'columns': columns
                        })
                except Exception as e:
                    logger.warning(f"Error checking table {table} in {db_path}: {e}")
            
            # Extract locations from each table
            for table_info in location_tables:
                table = table_info['name']
                columns = table_info['columns']
                
                # Build query
                query = f"SELECT * FROM {table} LIMIT 1000"
                
                try:
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        location = dict(row)
                        
                        # Add location to list
                        locations.append(location)
                except Exception as e:
                    logger.warning(f"Error extracting locations from {table} in {db_path}: {e}")
            
            conn.close()
            
            # Clean up temporary files
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            os.rmdir(temp_dir)
        
        except Exception as e:
            logger.error(f"Error extracting locations from {db_path}: {e}")
        
        return locations


def find_installed_applications(ios_root: str) -> List[Dict[str, Any]]:
    """
    Find installed applications on the iOS device
    
    Args:
        ios_root: iOS file system root directory
        
    Returns:
        List of dictionaries with app information
    """
    logger.info(f"Finding installed applications in {ios_root}")
    
    analyzer = AppAnalyzer(ios_root)
    return analyzer.find_installed_apps()


def analyze_application(ios_root: str, bundle_id: str) -> Dict[str, Any]:
    """
    Analyze a specific application by bundle ID
    
    Args:
        ios_root: iOS file system root directory
        bundle_id: Application bundle identifier
        
    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Analyzing application {bundle_id}")
    
    analyzer = AppAnalyzer(ios_root)
    apps = analyzer.find_installed_apps()
    
    # Find the requested app
    app = next((a for a in apps if a.get('bundle_id') == bundle_id), None)
    if not app:
        return {
            'bundle_id': bundle_id,
            'error': 'Application not found'
        }
    
    # Analyze the app
    analysis = analyzer.analyze_app_data(app)
    
    return analysis


def extract_application_data(ios_root: str, bundle_id: str, data_category: Optional[str] = None) -> Dict[str, Any]:
    """
    Extract data from a specific application
    
    Args:
        ios_root: iOS file system root directory
        bundle_id: Application bundle identifier
        data_category: Optional data category to focus on
        
    Returns:
        Dictionary with extracted data
    """
    logger.info(f"Extracting data from application {bundle_id}")
    
    analyzer = AppAnalyzer(ios_root)
    apps = analyzer.find_installed_apps()
    
    # Find the requested app
    app = next((a for a in apps if a.get('bundle_id') == bundle_id), None)
    if not app:
        return {
            'bundle_id': bundle_id,
            'error': 'Application not found'
        }
    
    # Extract data
    extraction = analyzer.extract_app_user_data(app, data_category)
    
    return extraction