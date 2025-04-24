# tools/specialized/locations.py - iOS location data analysis tools

import os
import sqlite3
import plistlib
import biplist
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
from tools.sqlite.analyzer import is_sqlite_database
from tools.plist.parser import parse_plist, is_plist_file
from utils.path_utils import find_files_by_extension
from utils.timestamp_utils import (
    mac_absolute_to_datetime, 
    convert_mac_absolute_to_unix, 
    timestamp_to_datetime, 
    detect_timestamp_type
)


class LocationAnalyzer:
    """
    Analyzer for iOS location data
    
    Extracts and analyzes location data from various iOS sources
    """
    
    def __init__(self, ios_root: str):
        """
        Initialize the location analyzer
        
        Args:
            ios_root: iOS file system root directory
        """
        self.ios_root = ios_root
        
        # Known location data paths
        self.location_paths = {
            # Significant locations (frequent locations)
            'significant_locations': os.path.join(ios_root, 'private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite'),
            
            # Location cache (iOS 10+)
            'location_cache': os.path.join(ios_root, 'private/var/mobile/Library/Caches/com.apple.routined'),
            
            # Location cache (iOS 9 and earlier)
            'legacy_location': os.path.join(ios_root, 'private/var/mobile/Library/Caches/locationd/consolidated.db'),
            
            # Location settings plists
            'location_settings': os.path.join(ios_root, 'private/var/mobile/Library/Preferences/com.apple.locationd.plist'),
            
            # Map search history
            'maps_history': os.path.join(ios_root, 'private/var/mobile/Library/Maps/History.plist'),
            
            # Cached map tiles
            'map_tiles': os.path.join(ios_root, 'private/var/mobile/Library/Maps/MapTiles.sqlitedb'),
            
            # Photos location data
            'photos_location': os.path.join(ios_root, 'private/var/mobile/Media/PhotoData/Photos.sqlite'),
            
            # Weather locations
            'weather_locations': os.path.join(ios_root, 'private/var/mobile/Library/Preferences/com.apple.weather.plist'),
            
            # Location services plists
            'location_services': os.path.join(ios_root, 'private/var/mobile/Library/Preferences/com.apple.locationd.plist'),
            
            # Geofence data
            'geofence': os.path.join(ios_root, 'private/var/mobile/Library/Caches/com.apple.geod')
        }
    
    def find_location_artifacts(self) -> Dict[str, Any]:
        """
        Find location-related artifacts in the iOS file system
        
        Returns:
            Dictionary with artifact information
        """
        logger.info(f"Finding location artifacts in {self.ios_root}")
        
        artifacts = {
            'databases': [],
            'plists': [],
            'caches': [],
            'files': []
        }
        
        # Check known paths
        for name, path in self.location_paths.items():
            if os.path.exists(path):
                artifact_info = {
                    'name': name,
                    'path': path,
                    'type': 'unknown'
                }
                
                if os.path.isdir(path):
                    artifact_info['type'] = 'directory'
                    
                    # Look for databases and plists inside this directory
                    db_files = find_files_by_extension(path, ['db', 'sqlite', 'sqlitedb'])
                    plist_files = find_files_by_extension(path, ['plist'])
                    
                    artifact_info['databases'] = []
                    artifact_info['plists'] = []
                    
                    for db_path in db_files:
                        if os.path.exists(db_path) and is_sqlite_database(db_path):
                            artifacts['databases'].append({
                                'name': os.path.basename(db_path),
                                'path': db_path,
                                'size': os.path.getsize(db_path),
                                'parent': name
                            })
                            artifact_info['databases'].append(os.path.basename(db_path))
                    
                    for plist_path in plist_files:
                        if os.path.exists(plist_path) and is_plist_file(plist_path):
                            artifacts['plists'].append({
                                'name': os.path.basename(plist_path),
                                'path': plist_path,
                                'size': os.path.getsize(plist_path),
                                'parent': name
                            })
                            artifact_info['plists'].append(os.path.basename(plist_path))
                    
                    artifacts['caches'].append(artifact_info)
                
                elif os.path.isfile(path):
                    artifact_info['size'] = os.path.getsize(path)
                    
                    if path.endswith(('.db', '.sqlite', '.sqlitedb')) and is_sqlite_database(path):
                        artifact_info['type'] = 'database'
                        artifacts['databases'].append({
                            'name': name,
                            'path': path,
                            'size': os.path.getsize(path)
                        })
                    
                    elif path.endswith('.plist') and is_plist_file(path):
                        artifact_info['type'] = 'plist'
                        artifacts['plists'].append({
                            'name': name,
                            'path': path,
                            'size': os.path.getsize(path)
                        })
                    
                    else:
                        artifact_info['type'] = 'file'
                        artifacts['files'].append(artifact_info)
        
        # Look for additional location-related databases
        locations_db_paths = self._find_location_databases()
        for db_path in locations_db_paths:
            if db_path not in [d['path'] for d in artifacts['databases']]:
                artifacts['databases'].append({
                    'name': os.path.basename(db_path),
                    'path': db_path,
                    'size': os.path.getsize(db_path),
                    'discovery_method': 'search'
                })
        
        logger.info(f"Found {len(artifacts['databases'])} location databases, {len(artifacts['plists'])} plists, and {len(artifacts['caches'])} location caches")
        return artifacts
    
    def _find_location_databases(self) -> List[str]:
        """
        Find location-related databases through broader search
        
        Returns:
            List of database paths
        """
        location_db_paths = []
        
        # Paths to search
        search_paths = [
            os.path.join(self.ios_root, 'private/var/mobile/Library/Caches'),
            os.path.join(self.ios_root, 'private/var/mobile/Library/Maps'),
            os.path.join(self.ios_root, 'private/var/mobile/Library/Preferences'),
            os.path.join(self.ios_root, 'private/var/mobile/Containers/Data/Application')
        ]
        
        # Location-related keywords
        location_keywords = ['location', 'gps', 'geo', 'map', 'places', 'position', 'route', 'visit']
        
        for search_path in search_paths:
            if os.path.exists(search_path) and os.path.isdir(search_path):
                # Find all SQLite databases
                db_paths = find_files_by_extension(search_path, ['db', 'sqlite', 'sqlitedb'])
                
                for db_path in db_paths:
                    db_name = os.path.basename(db_path).lower()
                    
                    # Check if the database name contains a location keyword
                    if any(keyword in db_name for keyword in location_keywords):
                        if os.path.exists(db_path) and is_sqlite_database(db_path):
                            location_db_paths.append(db_path)
                            continue
                    
                    # If not found by name, check the database schema for location tables
                    if os.path.exists(db_path) and is_sqlite_database(db_path) and self._is_location_database(db_path):
                        location_db_paths.append(db_path)
        
        return location_db_paths
    
    def _is_location_database(self, db_path: str) -> bool:
        """
        Check if a database contains location-related tables
        
        Args:
            db_path: Path to the SQLite database
            
        Returns:
            True if this appears to be a location database
        """
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
            
            # Execute "PRAGMA journal_mode=OFF" to prevent journal file creation
            conn.execute("PRAGMA journal_mode=OFF")
            
            # Disable WAL mode to prevent modification
            conn.execute("PRAGMA locking_mode=NORMAL")
            
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0].lower() for row in cursor.fetchall()]
            
            # Location-related table keywords
            location_table_keywords = ['location', 'place', 'visit', 'coordinate', 'position', 'geo', 
                                      'latitude', 'longitude', 'waypoint', 'route', 'map', 'gps']
            
            # Check if any table name contains a location keyword
            if any(any(keyword in table for keyword in location_table_keywords) for table in tables):
                conn.close()
                
                # Clean up temporary files
                os.remove(temp_db_path)
                if os.path.exists(f"{temp_db_path}-wal"):
                    os.remove(f"{temp_db_path}-wal")
                os.rmdir(temp_dir)
                
                return True
            
            # Check table schemas for location-related columns
            location_column_keywords = ['latitude', 'longitude', 'lat', 'long', 'lon', 'coord', 
                                       'location', 'accuracy', 'altitude', 'bearing', 'speed']
            
            for table in tables:
                try:
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row[1].lower() for row in cursor.fetchall()]
                    
                    if any(any(keyword in column for keyword in location_column_keywords) for column in columns):
                        conn.close()
                        
                        # Clean up temporary files
                        os.remove(temp_db_path)
                        if os.path.exists(f"{temp_db_path}-wal"):
                            os.remove(f"{temp_db_path}-wal")
                        os.rmdir(temp_dir)
                        
                        return True
                except Exception:
                    continue
            
            conn.close()
            
            # Clean up temporary files
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            os.rmdir(temp_dir)
            
            return False
        
        except Exception as e:
            logger.warning(f"Error checking if {db_path} is a location database: {e}")
            return False
    
    def analyze_significant_locations(self) -> Dict[str, Any]:
        """
        Analyze the significant locations database
        
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing significant locations")
        
        sig_loc_path = self.location_paths['significant_locations']
        if not os.path.exists(sig_loc_path) or not os.path.isfile(sig_loc_path):
            return {
                'error': f"Significant locations database not found at {sig_loc_path}"
            }
        
        try:
            # Create a temporary copy to prevent modification
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, os.path.basename(sig_loc_path))
            
            # Copy the database
            shutil.copy2(sig_loc_path, temp_db_path)
            
            # Check for WAL file
            wal_path = f"{sig_loc_path}-wal"
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
            
            # Check for known tables in the significant locations database
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            analysis_results = {
                'path': sig_loc_path,
                'locations': [],
                'visits': [],
                'statistics': {}
            }
            
            # Extract locations
            if 'ZRTLEARNEDLOCATION' in tables:
                # iOS 11+
                cursor.execute("""
                    SELECT 
                        ZRTLEARNEDLOCATION.Z_PK as id,
                        ZRTLEARNEDLOCATION.ZLATITUDE as latitude,
                        ZRTLEARNEDLOCATION.ZLONGITUDE as longitude,
                        ZRTLEARNEDLOCATION.ZCONFIDENCE as confidence,
                        ZRTLEARNEDLOCATION.ZENTRYDATE as entry_date,
                        ZRTLEARNEDLOCATION.ZEXITDATE as exit_date,
                        ZRTLEARNEDLOCATIONOFINTEREST.ZDISPLAYNAME as display_name,
                        ZRTLEARNEDLOCATIONOFINTEREST.ZCOUNTRY as country,
                        ZRTLEARNEDLOCATIONOFINTEREST.ZSTATE as state,
                        ZRTLEARNEDLOCATIONOFINTEREST.ZCITY as city,
                        ZRTLEARNEDLOCATIONOFINTEREST.ZPOSTALCODE as postal_code,
                        ZRTLEARNEDLOCATIONOFINTEREST.ZSUBLOCALITY as sublocality
                    FROM ZRTLEARNEDLOCATION
                    LEFT JOIN ZRTLEARNEDLOCATIONOFINTEREST ON ZRTLEARNEDLOCATION.ZLOCATIONOFINTEREST = ZRTLEARNEDLOCATIONOFINTEREST.Z_PK
                    LIMIT 1000
                """)
            elif 'ZRTCLLOCATIONMO' in tables:
                # iOS 10
                cursor.execute("""
                    SELECT 
                        ZRTCLLOCATIONMO.Z_PK as id,
                        ZRTCLLOCATIONMO.ZLATITUDE as latitude,
                        ZRTCLLOCATIONMO.ZLONGITUDE as longitude,
                        ZRTCLLOCATIONMO.ZCONFIDENCE as confidence,
                        ZRTCLLOCATIONMO.ZENTRYDATE as entry_date,
                        ZRTCLLOCATIONMO.ZEXITDATE as exit_date,
                        ZRTADDRESSMO.ZCOUNTRY as country,
                        ZRTADDRESSMO.ZSTATE as state,
                        ZRTADDRESSMO.ZCITY as city,
                        ZRTADDRESSMO.ZPOSTALCODE as postal_code,
                        ZRTADDRESSMO.ZSUBLOCALITY as sublocality
                    FROM ZRTCLLOCATIONMO
                    LEFT JOIN ZRTADDRESSMO ON ZRTCLLOCATIONMO.ZADDRESS = ZRTADDRESSMO.Z_PK
                    LIMIT 1000
                """)
            elif 'Location' in tables:
                # Older iOS versions
                cursor.execute("""
                    SELECT 
                        Location.id as id,
                        Location.latitude as latitude,
                        Location.longitude as longitude,
                        Location.confidence as confidence,
                        Location.entry_date as entry_date,
                        Location.exit_date as exit_date,
                        Location.address as address
                    FROM Location
                    LIMIT 1000
                """)
            
            # Process location results
            rows = cursor.fetchall()
            for row in rows:
                location = dict(row)
                
                # Convert timestamps
                for key in ['entry_date', 'exit_date']:
                    if key in location and location[key]:
                        timestamp = location[key]
                        timestamp_type = detect_timestamp_type(timestamp)
                        dt = timestamp_to_datetime(timestamp, timestamp_type)
                        
                        if dt:
                            location[f"{key}_formatted"] = dt.isoformat()
                
                analysis_results['locations'].append(location)
            
            # Extract visits
            if 'ZRTVISITMO' in tables:
                # iOS 11+
                cursor.execute("""
                    SELECT 
                        ZRTVISITMO.Z_PK as id,
                        ZRTVISITMO.ZENTRYDATE as entry_date,
                        ZRTVISITMO.ZEXITDATE as exit_date,
                        ZRTVISITMO.ZCONFIDENCE as confidence,
                        ZRTLEARNEDLOCATION.ZLATITUDE as latitude,
                        ZRTLEARNEDLOCATION.ZLONGITUDE as longitude,
                        ZRTLEARNEDLOCATIONOFINTEREST.ZDISPLAYNAME as display_name
                    FROM ZRTVISITMO
                    LEFT JOIN ZRTLEARNEDLOCATION ON ZRTVISITMO.ZLOCATION = ZRTLEARNEDLOCATION.Z_PK
                    LEFT JOIN ZRTLEARNEDLOCATIONOFINTEREST ON ZRTLEARNEDLOCATION.ZLOCATIONOFINTEREST = ZRTLEARNEDLOCATIONOFINTEREST.Z_PK
                    ORDER BY ZRTVISITMO.ZENTRYDATE DESC
                    LIMIT 1000
                """)
            elif 'ZRTVISIT' in tables:
                # iOS 10
                cursor.execute("""
                    SELECT 
                        ZRTVISIT.Z_PK as id,
                        ZRTVISIT.ZARRIVALDATE as entry_date,
                        ZRTVISIT.ZDEPARTUREDATE as exit_date,
                        ZRTVISIT.ZCONFIDENCE as confidence,
                        ZRTCLLOCATIONMO.ZLATITUDE as latitude,
                        ZRTCLLOCATIONMO.ZLONGITUDE as longitude
                    FROM ZRTVISIT
                    LEFT JOIN ZRTCLLOCATIONMO ON ZRTVISIT.ZLOCATION = ZRTCLLOCATIONMO.Z_PK
                    ORDER BY ZRTVISIT.ZARRIVALDATE DESC
                    LIMIT 1000
                """)
            
            # Process visit results
            rows = cursor.fetchall()
            for row in rows:
                visit = dict(row)
                
                # Convert timestamps
                for key in ['entry_date', 'exit_date']:
                    if key in visit and visit[key]:
                        timestamp = visit[key]
                        timestamp_type = detect_timestamp_type(timestamp)
                        dt = timestamp_to_datetime(timestamp, timestamp_type)
                        
                        if dt:
                            visit[f"{key}_formatted"] = dt.isoformat()
                
                analysis_results['visits'].append(visit)
            
            # Generate statistics
            analysis_results['statistics'] = {
                'location_count': len(analysis_results['locations']),
                'visit_count': len(analysis_results['visits'])
            }
            
            # Get date range
            if analysis_results['visits']:
                entry_dates = [v.get('entry_date') for v in analysis_results['visits'] if v.get('entry_date')]
                exit_dates = [v.get('exit_date') for v in analysis_results['visits'] if v.get('exit_date')]
                
                if entry_dates:
                    min_date = min(entry_dates)
                    min_date_type = detect_timestamp_type(min_date)
                    min_dt = timestamp_to_datetime(min_date, min_date_type)
                    
                    if min_dt:
                        analysis_results['statistics']['oldest_date'] = min_dt.isoformat()
                
                if exit_dates:
                    max_date = max(exit_dates)
                    max_date_type = detect_timestamp_type(max_date)
                    max_dt = timestamp_to_datetime(max_date, max_date_type)
                    
                    if max_dt:
                        analysis_results['statistics']['newest_date'] = max_dt.isoformat()
            
            conn.close()
            
            # Clean up temporary files
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            os.rmdir(temp_dir)
            
            return analysis_results
        
        except Exception as e:
            logger.error(f"Error analyzing significant locations: {e}")
            return {
                'path': sig_loc_path,
                'error': str(e)
            }
    
    def analyze_maps_history(self) -> Dict[str, Any]:
        """
        Analyze Apple Maps search history
        
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing Maps search history")
        
        maps_history_path = self.location_paths['maps_history']
        if not os.path.exists(maps_history_path) or not os.path.isfile(maps_history_path):
            return {
                'error': f"Maps history not found at {maps_history_path}"
            }
        
        try:
            # Parse the plist
            history_plist = parse_plist(maps_history_path)
            
            analysis_results = {
                'path': maps_history_path,
                'searches': [],
                'statistics': {}
            }
            
            # Extract search history
            if 'MapsSearchHistory' in history_plist:
                searches = history_plist['MapsSearchHistory']
                
                for search in searches:
                    search_info = {
                        'title': search.get('title', ''),
                        'subtitle': search.get('subtitle', ''),
                        'address': search.get('addressDictionary', {})
                    }
                    
                    # Extract coordinates
                    if 'coordinate' in search:
                        coords = search['coordinate']
                        if isinstance(coords, dict) and 'latitude' in coords and 'longitude' in coords:
                            search_info['latitude'] = coords['latitude']
                            search_info['longitude'] = coords['longitude']
                    
                    # Extract timestamp
                    if 'date' in search:
                        timestamp = search['date']
                        if isinstance(timestamp, datetime):
                            search_info['date'] = timestamp.isoformat()
                    
                    analysis_results['searches'].append(search_info)
            
            # Generate statistics
            analysis_results['statistics'] = {
                'search_count': len(analysis_results['searches'])
            }
            
            # Get date range
            if analysis_results['searches']:
                dates = []
                for search in analysis_results['searches']:
                    if 'date' in search:
                        try:
                            dt = datetime.fromisoformat(search['date'])
                            dates.append(dt)
                        except ValueError:
                            pass
                
                if dates:
                    analysis_results['statistics']['oldest_date'] = min(dates).isoformat()
                    analysis_results['statistics']['newest_date'] = max(dates).isoformat()
            
            return analysis_results
        
        except Exception as e:
            logger.error(f"Error analyzing Maps history: {e}")
            return {
                'path': maps_history_path,
                'error': str(e)
            }
    
    def analyze_location_services(self) -> Dict[str, Any]:
        """
        Analyze location services settings
        
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing location services settings")
        
        location_settings_path = self.location_paths['location_services']
        if not os.path.exists(location_settings_path) or not os.path.isfile(location_settings_path):
            return {
                'error': f"Location services settings not found at {location_settings_path}"
            }
        
        try:
            # Parse the plist
            settings_plist = parse_plist(location_settings_path)
            
            analysis_results = {
                'path': location_settings_path,
                'settings': {},
                'app_permissions': [],
                'system_services': []
            }
            
            # Extract location services settings
            if 'LocationServicesEnabled' in settings_plist:
                analysis_results['settings']['location_services_enabled'] = settings_plist['LocationServicesEnabled']
            
            # Extract app permissions
            if 'clients' in settings_plist and isinstance(settings_plist['clients'], dict):
                clients = settings_plist['clients']
                
                for app_id, permissions in clients.items():
                    if isinstance(permissions, dict):
                        app_info = {
                            'bundle_id': app_id,
                            'authorized': permissions.get('Authorization', 0),
                            'authorization_status': self._get_auth_status(permissions.get('Authorization', 0)),
                            'location_tracking_enabled': permissions.get('LocationTrackingEnabled', False),
                            'active': permissions.get('Active', False),
                            'precise_location': permissions.get('PreciseLocationTracking', True)
                        }
                        
                        # Get timestamp of last usage
                        if 'LastUsageTimeStamp' in permissions:
                            timestamp = permissions['LastUsageTimeStamp']
                            timestamp_type = detect_timestamp_type(timestamp)
                            dt = timestamp_to_datetime(timestamp, timestamp_type)
                            
                            if dt:
                                app_info['last_usage'] = dt.isoformat()
                        
                        analysis_results['app_permissions'].append(app_info)
            
            # Extract system services permissions
            if 'system_services' in settings_plist and isinstance(settings_plist['system_services'], dict):
                services = settings_plist['system_services']
                
                for service_id, permissions in services.items():
                    if isinstance(permissions, dict):
                        service_info = {
                            'service_id': service_id,
                            'enabled': permissions.get('Enabled', False)
                        }
                        
                        analysis_results['system_services'].append(service_info)
            
            return analysis_results
        
        except Exception as e:
            logger.error(f"Error analyzing location services settings: {e}")
            return {
                'path': location_settings_path,
                'error': str(e)
            }
    
    def _get_auth_status(self, status: int) -> str:
        """
        Convert authorization status to human-readable string
        
        Args:
            status: Authorization status code
            
        Returns:
            Human-readable status string
        """
        if status == 0:
            return "Not Determined"
        elif status == 1:
            return "Restricted"
        elif status == 2:
            return "Denied"
        elif status == 3:
            return "Always Authorized"
        elif status == 4:
            return "Authorized When In Use"
        else:
            return f"Unknown ({status})"
    
    def extract_photo_locations(self, limit: int = 1000) -> Dict[str, Any]:
        """
        Extract location data from the Photos database
        
        Args:
            limit: Maximum number of photos to analyze
            
        Returns:
            Dictionary with extracted locations
        """
        logger.info(f"Extracting photo locations")
        
        photos_db_path = self.location_paths['photos_location']
        if not os.path.exists(photos_db_path) or not os.path.isfile(photos_db_path):
            return {
                'error': f"Photos database not found at {photos_db_path}"
            }
        
        try:
            # Create a temporary copy to prevent modification
            temp_dir = tempfile.mkdtemp()
            temp_db_path = os.path.join(temp_dir, os.path.basename(photos_db_path))
            
            # Copy the database
            shutil.copy2(photos_db_path, temp_db_path)
            
            # Check for WAL file
            wal_path = f"{photos_db_path}-wal"
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
            
            # Check for known tables in the Photos database
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            extraction_results = {
                'path': photos_db_path,
                'photo_locations': [],
                'statistics': {}
            }
            
            # Extract photo locations
            # The schema varies significantly between iOS versions
            # Try different known schemas
            
            # iOS 10+
            if 'ZASSET' in tables and 'ZADDITIONALASSETATTRIBUTES' in tables:
                try:
                    cursor.execute("""
                        SELECT 
                            ZASSET.Z_PK as id,
                            ZASSET.ZDATECREATED as date_created,
                            ZADDITIONALASSETATTRIBUTES.ZLATITUDE as latitude,
                            ZADDITIONALASSETATTRIBUTES.ZLONGITUDE as longitude,
                            ZADDITIONALASSETATTRIBUTES.ZREVERSELOCATIONDATA as location_data
                        FROM ZASSET
                        JOIN ZADDITIONALASSETATTRIBUTES ON ZASSET.Z_PK = ZADDITIONALASSETATTRIBUTES.ZASSET
                        WHERE ZADDITIONALASSETATTRIBUTES.ZLATITUDE IS NOT NULL
                        AND ZADDITIONALASSETATTRIBUTES.ZLONGITUDE IS NOT NULL
                        ORDER BY ZASSET.ZDATECREATED DESC
                        LIMIT ?
                    """, (limit,))
                    
                    rows = cursor.fetchall()
                    for row in rows:
                        photo = dict(row)
                        
                        # Convert timestamp
                        if 'date_created' in photo and photo['date_created']:
                            timestamp = photo['date_created']
                            timestamp_type = detect_timestamp_type(timestamp)
                            dt = timestamp_to_datetime(timestamp, timestamp_type)
                            
                            if dt:
                                photo['date_created_formatted'] = dt.isoformat()
                        
                        extraction_results['photo_locations'].append(photo)
                except Exception as e:
                    logger.warning(f"Error extracting iOS 10+ photo locations: {e}")
            
            # iOS 8-9
            elif 'ZASSET' in tables and 'ZLOCATION' in tables:
                try:
                    cursor.execute("""
                        SELECT 
                            ZASSET.Z_PK as id,
                            ZASSET.ZDATECREATED as date_created,
                            ZLOCATION.ZLATITUDE as latitude,
                            ZLOCATION.ZLONGITUDE as longitude,
                            ZLOCATION.ZPLACENAME as place_name,
                            ZLOCATION.ZCOUNTRY as country,
                            ZLOCATION.ZCITY as city
                        FROM ZASSET
                        JOIN ZLOCATION ON ZASSET.ZLOCATION = ZLOCATION.Z_PK
                        WHERE ZLOCATION.ZLATITUDE IS NOT NULL
                        AND ZLOCATION.ZLONGITUDE IS NOT NULL
                        ORDER BY ZASSET.ZDATECREATED DESC
                        LIMIT ?
                    """, (limit,))
                    
                    rows = cursor.fetchall()
                    for row in rows:
                        photo = dict(row)
                        
                        # Convert timestamp
                        if 'date_created' in photo and photo['date_created']:
                            timestamp = photo['date_created']
                            timestamp_type = detect_timestamp_type(timestamp)
                            dt = timestamp_to_datetime(timestamp, timestamp_type)
                            
                            if dt:
                                photo['date_created_formatted'] = dt.isoformat()
                        
                        extraction_results['photo_locations'].append(photo)
                except Exception as e:
                    logger.warning(f"Error extracting iOS 8-9 photo locations: {e}")
            
            # iOS 7 and earlier
            elif 'ZGENERICASSET' in tables:
                try:
                    cursor.execute("""
                        SELECT 
                            ZGENERICASSET.Z_PK as id,
                            ZGENERICASSET.ZDATECREATED as date_created,
                            ZGENERICASSET.ZLATITUDE as latitude,
                            ZGENERICASSET.ZLONGITUDE as longitude
                        FROM ZGENERICASSET
                        WHERE ZGENERICASSET.ZLATITUDE IS NOT NULL
                        AND ZGENERICASSET.ZLONGITUDE IS NOT NULL
                        AND ZGENERICASSET.ZLATITUDE <> 0
                        AND ZGENERICASSET.ZLONGITUDE <> 0
                        ORDER BY ZGENERICASSET.ZDATECREATED DESC
                        LIMIT ?
                    """, (limit,))
                    
                    rows = cursor.fetchall()
                    for row in rows:
                        photo = dict(row)
                        
                        # Convert timestamp
                        if 'date_created' in photo and photo['date_created']:
                            timestamp = photo['date_created']
                            timestamp_type = detect_timestamp_type(timestamp)
                            dt = timestamp_to_datetime(timestamp, timestamp_type)
                            
                            if dt:
                                photo['date_created_formatted'] = dt.isoformat()
                        
                        extraction_results['photo_locations'].append(photo)
                except Exception as e:
                    logger.warning(f"Error extracting iOS 7 photo locations: {e}")
            
            # Generate statistics
            extraction_results['statistics'] = {
                'photo_count': len(extraction_results['photo_locations'])
            }
            
            # Get date range
            if extraction_results['photo_locations']:
                dates = []
                for photo in extraction_results['photo_locations']:
                    if 'date_created_formatted' in photo:
                        try:
                            dates.append(photo['date_created_formatted'])
                        except Exception:
                            pass
                
                if dates:
                    extraction_results['statistics']['oldest_date'] = min(dates)
                    extraction_results['statistics']['newest_date'] = max(dates)
            
            conn.close()
            
            # Clean up temporary files
            os.remove(temp_db_path)
            if os.path.exists(f"{temp_db_path}-wal"):
                os.remove(f"{temp_db_path}-wal")
            os.rmdir(temp_dir)
            
            return extraction_results
        
        except Exception as e:
            logger.error(f"Error extracting photo locations: {e}")
            return {
                'path': photos_db_path,
                'error': str(e)
            }
    
    def generate_location_timeline(self, start_date: Optional[datetime] = None, 
                                  end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive timeline of location data
        
        Args:
            start_date: Optional start date for the timeline
            end_date: Optional end date for the timeline
            
        Returns:
            Dictionary with timeline data
        """
        logger.info(f"Generating location timeline")
        
        timeline_results = {
            'timeline_entries': [],
            'statistics': {},
            'sources': []
        }
        
        try:
            # Get data from all location sources
            
            # 1. Significant locations
            sig_locations = self.analyze_significant_locations()
            if 'error' not in sig_locations:
                # Add visits to timeline
                for visit in sig_locations.get('visits', []):
                    if 'entry_date_formatted' in visit:
                        entry_date = None
                        try:
                            entry_date = datetime.fromisoformat(visit['entry_date_formatted'])
                        except ValueError:
                            pass
                        
                        # Skip if outside date range
                        if (start_date and entry_date and entry_date < start_date) or \
                           (end_date and entry_date and entry_date > end_date):
                            continue
                        
                        timeline_entry = {
                            'timestamp': visit['entry_date_formatted'],
                            'type': 'significant_location_visit',
                            'latitude': visit.get('latitude'),
                            'longitude': visit.get('longitude'),
                            'description': visit.get('display_name', 'Unknown location'),
                            'duration': None
                        }
                        
                        # Calculate duration if exit date available
                        if 'exit_date_formatted' in visit:
                            try:
                                exit_date = datetime.fromisoformat(visit['exit_date_formatted'])
                                entry_date = datetime.fromisoformat(visit['entry_date_formatted'])
                                duration = (exit_date - entry_date).total_seconds()
                                timeline_entry['duration'] = duration
                                timeline_entry['duration_formatted'] = self._format_duration(duration)
                            except ValueError:
                                pass
                        
                        timeline_results['timeline_entries'].append(timeline_entry)
                
                timeline_results['sources'].append('significant_locations')
            
            # 2. Photo locations
            photo_locations = self.extract_photo_locations()
            if 'error' not in photo_locations:
                for photo in photo_locations.get('photo_locations', []):
                    if 'date_created_formatted' in photo:
                        date_created = None
                        try:
                            date_created = datetime.fromisoformat(photo['date_created_formatted'])
                        except ValueError:
                            pass
                        
                        # Skip if outside date range
                        if (start_date and date_created and date_created < start_date) or \
                           (end_date and date_created and date_created > end_date):
                            continue
                        
                        timeline_entry = {
                            'timestamp': photo['date_created_formatted'],
                            'type': 'photo',
                            'latitude': photo.get('latitude'),
                            'longitude': photo.get('longitude'),
                            'description': f"Photo taken at {photo.get('latitude')}, {photo.get('longitude')}"
                        }
                        
                        # Add location information if available
                        location_fields = ['place_name', 'city', 'country']
                        location_parts = []
                        for field in location_fields:
                            if field in photo and photo[field]:
                                location_parts.append(photo[field])
                        
                        if location_parts:
                            timeline_entry['description'] = f"Photo taken at {', '.join(location_parts)}"
                        
                        timeline_results['timeline_entries'].append(timeline_entry)
                
                timeline_results['sources'].append('photos')
            
            # 3. Maps history
            maps_history = self.analyze_maps_history()
            if 'error' not in maps_history:
                for search in maps_history.get('searches', []):
                    if 'date' in search:
                        search_date = None
                        try:
                            search_date = datetime.fromisoformat(search['date'])
                        except ValueError:
                            pass
                        
                        # Skip if outside date range
                        if (start_date and search_date and search_date < start_date) or \
                           (end_date and search_date and search_date > end_date):
                            continue
                        
                        title = search.get('title', 'Unknown location')
                        subtitle = search.get('subtitle', '')
                        
                        timeline_entry = {
                            'timestamp': search['date'],
                            'type': 'maps_search',
                            'latitude': search.get('latitude'),
                            'longitude': search.get('longitude'),
                            'description': f"Maps search: {title}"
                        }
                        
                        if subtitle:
                            timeline_entry['description'] += f" ({subtitle})"
                        
                        timeline_results['timeline_entries'].append(timeline_entry)
                
                timeline_results['sources'].append('maps_history')
            
            # Sort timeline entries by timestamp
            timeline_results['timeline_entries'].sort(key=lambda x: x['timestamp'])
            
            # Generate statistics
            timeline_results['statistics'] = {
                'entry_count': len(timeline_results['timeline_entries']),
                'source_count': len(timeline_results['sources'])
            }
            
            # Get date range
            if timeline_results['timeline_entries']:
                dates = []
                for entry in timeline_results['timeline_entries']:
                    if 'timestamp' in entry:
                        try:
                            dates.append(entry['timestamp'])
                        except Exception:
                            pass
                
                if dates:
                    timeline_results['statistics']['oldest_date'] = min(dates)
                    timeline_results['statistics']['newest_date'] = max(dates)
            
            return timeline_results
        
        except Exception as e:
            logger.error(f"Error generating location timeline: {e}")
            return {
                'error': str(e),
                'timeline_entries': [],
                'statistics': {},
                'sources': []
            }
    
    def _format_duration(self, seconds: float) -> str:
        """
        Format a duration in seconds as a human-readable string
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            Formatted duration string
        """
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{int(minutes)} minutes"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{int(hours)} hours"
        else:
            days = seconds / 86400
            return f"{int(days)} days"


def find_location_artifacts(ios_root: str) -> Dict[str, Any]:
    """
    Find location-related artifacts in the iOS file system
    
    Args:
        ios_root: iOS file system root directory
        
    Returns:
        Dictionary with artifact information
    """
    logger.info(f"Finding location artifacts in {ios_root}")
    
    analyzer = LocationAnalyzer(ios_root)
    return analyzer.find_location_artifacts()


def analyze_significant_locations(ios_root: str) -> Dict[str, Any]:
    """
    Analyze the significant locations database
    
    Args:
        ios_root: iOS file system root directory
        
    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Analyzing significant locations in {ios_root}")
    
    analyzer = LocationAnalyzer(ios_root)
    return analyzer.analyze_significant_locations()


def analyze_maps_history(ios_root: str) -> Dict[str, Any]:
    """
    Analyze Apple Maps search history
    
    Args:
        ios_root: iOS file system root directory
        
    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Analyzing Maps history in {ios_root}")
    
    analyzer = LocationAnalyzer(ios_root)
    return analyzer.analyze_maps_history()


def extract_photo_locations(ios_root: str, limit: int = 1000) -> Dict[str, Any]:
    """
    Extract location data from the Photos database
    
    Args:
        ios_root: iOS file system root directory
        limit: Maximum number of photos to analyze
        
    Returns:
        Dictionary with extracted locations
    """
    logger.info(f"Extracting photo locations in {ios_root}")
    
    analyzer = LocationAnalyzer(ios_root)
    return analyzer.extract_photo_locations(limit)


def generate_location_timeline(ios_root: str, start_date: Optional[str] = None, 
                              end_date: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a comprehensive timeline of location data
    
    Args:
        ios_root: iOS file system root directory
        start_date: Optional start date string (ISO format)
        end_date: Optional end date string (ISO format)
        
    Returns:
        Dictionary with timeline data
    """
    logger.info(f"Generating location timeline for {ios_root}")
    
    # Parse date strings if provided
    start_dt = None
    end_dt = None
    
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date)
        except ValueError:
            logger.warning(f"Invalid start date format: {start_date}")
    
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date)
        except ValueError:
            logger.warning(f"Invalid end date format: {end_date}")
    
    analyzer = LocationAnalyzer(ios_root)
    return analyzer.generate_location_timeline(start_dt, end_dt)