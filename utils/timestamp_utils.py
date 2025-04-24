# utils/timestamp_utils.py - Utilities for handling iOS timestamps

import datetime
import logging
import re
from typing import Optional, Union, Tuple, Dict, Any

# Set up logging
logger = logging.getLogger(__name__)

# Constants for timestamp conversion
MAC_ABSOLUTE_EPOCH = datetime.datetime(2001, 1, 1, 0, 0, 0)
UNIX_EPOCH = datetime.datetime(1970, 1, 1, 0, 0, 0)
COCOA_EPOCH = MAC_ABSOLUTE_EPOCH
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, 0, 0, 0)
MAC_ABSOLUTE_TO_UNIX_OFFSET = int((MAC_ABSOLUTE_EPOCH - UNIX_EPOCH).total_seconds())


def convert_mac_absolute_to_unix(timestamp: Union[int, float]) -> float:
    """
    Convert Mac Absolute Time (seconds since 2001-01-01) to Unix timestamp
    
    Args:
        timestamp: Mac Absolute Time timestamp
        
    Returns:
        Unix timestamp (seconds since 1970-01-01)
    """
    return timestamp + MAC_ABSOLUTE_TO_UNIX_OFFSET


def convert_unix_to_mac_absolute(timestamp: Union[int, float]) -> float:
    """
    Convert Unix timestamp to Mac Absolute Time
    
    Args:
        timestamp: Unix timestamp (seconds since 1970-01-01)
        
    Returns:
        Mac Absolute Time (seconds since 2001-01-01)
    """
    return timestamp - MAC_ABSOLUTE_TO_UNIX_OFFSET


def mac_absolute_to_datetime(timestamp: Union[int, float], is_nano: bool = False) -> datetime.datetime:
    """
    Convert Mac Absolute Time to datetime object
    
    Args:
        timestamp: Mac Absolute Time timestamp
        is_nano: Whether the timestamp is in nanoseconds (iOS often uses nanoseconds)
        
    Returns:
        datetime object
    """
    if is_nano:
        timestamp = timestamp / 1e9
    
    return MAC_ABSOLUTE_EPOCH + datetime.timedelta(seconds=timestamp)


def unix_to_datetime(timestamp: Union[int, float], is_milli: bool = False) -> datetime.datetime:
    """
    Convert Unix timestamp to datetime object
    
    Args:
        timestamp: Unix timestamp
        is_milli: Whether the timestamp is in milliseconds
        
    Returns:
        datetime object
    """
    if is_milli:
        timestamp = timestamp / 1000
    
    return datetime.datetime.fromtimestamp(timestamp)


def detect_timestamp_type(timestamp: Union[int, float]) -> str:
    """
    Try to detect the type of timestamp based on value range
    
    Args:
        timestamp: The timestamp value
        
    Returns:
        Timestamp type ('unix', 'unix_milli', 'mac_absolute', 'mac_absolute_nano', 'filetime', or 'unknown')
    """
    # Convert to int if it's a whole number
    if timestamp == int(timestamp):
        timestamp = int(timestamp)
    
    # Get timestamp length for integers
    if isinstance(timestamp, int):
        length = len(str(abs(timestamp)))
    else:
        # For floats, consider the integer part
        length = len(str(int(abs(timestamp))))
    
    # Heuristics for timestamp types
    current_year = datetime.datetime.now().year
    
    # Unix timestamp (seconds since 1970-01-01)
    # Typically 9-10 digits for recent dates (as of 2024)
    if 9 <= length <= 10:
        try:
            dt = datetime.datetime.fromtimestamp(timestamp)
            # Check if date is reasonable (between 1980 and current year + 1)
            if 1980 <= dt.year <= current_year + 1:
                return 'unix'
        except (ValueError, OverflowError):
            pass
    
    # Unix timestamp in milliseconds
    # Typically 12-13 digits for recent dates
    if 12 <= length <= 13:
        try:
            dt = datetime.datetime.fromtimestamp(timestamp / 1000)
            if 1980 <= dt.year <= current_year + 1:
                return 'unix_milli'
        except (ValueError, OverflowError):
            pass
    
    # Mac Absolute Time (seconds since 2001-01-01)
    # Typically 8-9 digits for recent dates
    if 8 <= length <= 9:
        try:
            dt = MAC_ABSOLUTE_EPOCH + datetime.timedelta(seconds=timestamp)
            if 2001 <= dt.year <= current_year + 1:
                return 'mac_absolute'
        except (ValueError, OverflowError):
            pass
    
    # Mac Absolute Time in nanoseconds
    # Typically 17-19 digits for recent dates
    if 17 <= length <= 19:
        try:
            dt = MAC_ABSOLUTE_EPOCH + datetime.timedelta(seconds=timestamp / 1e9)
            if 2001 <= dt.year <= current_year + 1:
                return 'mac_absolute_nano'
        except (ValueError, OverflowError):
            pass
    
    # Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    # Typically very large numbers (18+ digits)
    if length >= 16:
        try:
            seconds_since_filetime_epoch = timestamp / 10000000
            dt = FILETIME_EPOCH + datetime.timedelta(seconds=seconds_since_filetime_epoch)
            if 1601 <= dt.year <= current_year + 1:
                return 'filetime'
        except (ValueError, OverflowError):
            pass
    
    return 'unknown'


def timestamp_to_datetime(timestamp: Union[int, float], timestamp_type: Optional[str] = None) -> Optional[datetime.datetime]:
    """
    Convert a timestamp of any supported type to a datetime object
    
    Args:
        timestamp: The timestamp value
        timestamp_type: Type of timestamp ('unix', 'unix_milli', 'mac_absolute', 'mac_absolute_nano', 'filetime')
            If None, the type will be auto-detected
            
    Returns:
        datetime object or None if conversion fails
    """
    # Auto-detect timestamp type if not specified
    if timestamp_type is None:
        timestamp_type = detect_timestamp_type(timestamp)
    
    try:
        if timestamp_type == 'unix':
            return unix_to_datetime(timestamp)
        elif timestamp_type == 'unix_milli':
            return unix_to_datetime(timestamp, is_milli=True)
        elif timestamp_type == 'mac_absolute':
            return mac_absolute_to_datetime(timestamp)
        elif timestamp_type == 'mac_absolute_nano':
            return mac_absolute_to_datetime(timestamp, is_nano=True)
        elif timestamp_type == 'filetime':
            seconds_since_filetime_epoch = timestamp / 10000000
            return FILETIME_EPOCH + datetime.timedelta(seconds=seconds_since_filetime_epoch)
        else:
            logger.warning(f"Unknown timestamp type: {timestamp_type}")
            return None
    except Exception as e:
        logger.error(f"Error converting timestamp {timestamp} of type {timestamp_type}: {e}")
        return None


def format_datetime(dt: datetime.datetime, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format a datetime object as a string
    
    Args:
        dt: datetime object
        format_str: Format string for strftime
        
    Returns:
        Formatted datetime string
    """
    return dt.strftime(format_str)


def format_timestamp(timestamp: Union[int, float], timestamp_type: Optional[str] = None, 
                    format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format a timestamp as a human-readable string
    
    Args:
        timestamp: The timestamp value
        timestamp_type: Type of timestamp (auto-detected if None)
        format_str: Format string for datetime
        
    Returns:
        Formatted timestamp string
    """
    dt = timestamp_to_datetime(timestamp, timestamp_type)
    if dt:
        return format_datetime(dt, format_str)
    else:
        return f"Unknown timestamp: {timestamp}"


def extract_timestamps_from_data(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Extract and identify timestamps from a data structure
    
    Args:
        data: Dictionary containing data to analyze
        
    Returns:
        Dictionary mapping field names to timestamp information
    """
    results = {}
    
    # Common timestamp field names
    timestamp_fields = [
        'date', 'time', 'timestamp', 'created', 'modified', 'accessed',
        'creation_date', 'modification_date', 'access_date',
        'date_created', 'date_modified', 'date_accessed',
        'start_date', 'end_date', 'expires', 'expiration',
        'last_used', 'first_used', 'birth_time', 'death_time',
        'last_opened', 'last_viewed', 'last_played', 'last_modified'
    ]
    
    # Suffixes to check
    timestamp_suffixes = [
        '_at', '_date', '_time', '_timestamp', '_on', '_ts'
    ]
    
    # Recursively search for timestamp fields
    def search_timestamps(data_dict, prefix=''):
        if not isinstance(data_dict, dict):
            return
        
        for key, value in data_dict.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            # Check if this is potentially a timestamp field
            is_timestamp_field = False
            
            # Check field name against known timestamp fields
            key_lower = key.lower()
            if key_lower in timestamp_fields:
                is_timestamp_field = True
            
            # Check for timestamp suffixes
            for suffix in timestamp_suffixes:
                if key_lower.endswith(suffix):
                    is_timestamp_field = True
                    break
            
            # Process value if it's a potential timestamp
            if is_timestamp_field and isinstance(value, (int, float)):
                timestamp_type = detect_timestamp_type(value)
                dt = timestamp_to_datetime(value, timestamp_type)
                
                if dt:
                    results[full_key] = {
                        'value': value,
                        'type': timestamp_type,
                        'datetime': dt,
                        'formatted': format_datetime(dt)
                    }
            
            # Recursively search nested dictionaries
            if isinstance(value, dict):
                search_timestamps(value, full_key)
            
            # Search through lists for dictionaries
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        search_timestamps(item, f"{full_key}[{i}]")
    
    # Start the search
    search_timestamps(data)
    
    return results


def parse_iso8601_timestamp(timestamp_str: str) -> Optional[datetime.datetime]:
    """
    Parse an ISO 8601 formatted timestamp string
    
    Args:
        timestamp_str: ISO 8601 timestamp string
        
    Returns:
        datetime object or None if parsing fails
    """
    try:
        # Try parsing with various ISO 8601 formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',  # With microseconds and Z
            '%Y-%m-%dT%H:%M:%SZ',     # With Z
            '%Y-%m-%dT%H:%M:%S.%f',   # With microseconds
            '%Y-%m-%dT%H:%M:%S',      # Basic ISO format
            '%Y-%m-%d %H:%M:%S.%f',   # Space instead of T, with microseconds
            '%Y-%m-%d %H:%M:%S'       # Space instead of T
        ]
        
        for format_str in formats:
            try:
                return datetime.datetime.strptime(timestamp_str, format_str)
            except ValueError:
                continue
        
        # Try with timezone offset
        if '+' in timestamp_str or '-' in timestamp_str:
            match = re.match(r'(.+)([+-])(\d{2}):?(\d{2}), timestamp_str)
            if match:
                base_str, sign, hours, minutes = match.groups()
                # Parse the base timestamp without timezone
                base_dt = parse_iso8601_timestamp(base_str)
                if base_dt:
                    # Apply timezone offset
                    offset = datetime.timedelta(hours=int(hours), minutes=int(minutes))
                    if sign == '-':
                        base_dt += offset
                    else:
                        base_dt -= offset
                    return base_dt
        
        return None
    except Exception as e:
        logger.error(f"Error parsing ISO 8601 timestamp {timestamp_str}: {e}")
        return None


def parse_apple_time_string(timestamp_str: str) -> Optional[datetime.datetime]:
    """
    Parse various Apple time string formats
    
    Args:
        timestamp_str: Apple time string
        
    Returns:
        datetime object or None if parsing fails
    """
    try:
        # Check for ISO 8601 format first
        dt = parse_iso8601_timestamp(timestamp_str)
        if dt:
            return dt
        
        # Apple often uses formats like "Sat Dec 31 23:59:59 UTC 2022"
        try:
            return datetime.datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Z %Y')
        except ValueError:
            pass
        
        # Try without timezone
        try:
            return datetime.datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Y')
        except ValueError:
            pass
        
        # Another Apple format: "2022-12-31 23:59:59 +0000"
        try:
            # Strip timezone for now
            if '+' in timestamp_str or '-' in timestamp_str:
                ts_parts = timestamp_str.split(' ')
                if len(ts_parts) >= 3:
                    return datetime.datetime.strptime(f"{ts_parts[0]} {ts_parts[1]}", '%Y-%m-%d %H:%M:%S')
        except ValueError:
            pass
        
        return None
    except Exception as e:
        logger.error(f"Error parsing Apple time string {timestamp_str}: {e}")
        return None


def create_timestamp_timeline(timestamps: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Create a chronological timeline from extracted timestamps
    
    Args:
        timestamps: Dictionary of timestamp information
        
    Returns:
        List of timeline events sorted by datetime
    """
    timeline = []
    
    for field_name, timestamp_info in timestamps.items():
        dt = timestamp_info.get('datetime')
        if dt:
            event = {
                'datetime': dt,
                'field': field_name,
                'value': timestamp_info.get('value'),
                'formatted': timestamp_info.get('formatted', format_datetime(dt)),
                'type': timestamp_info.get('type', 'unknown')
            }
            timeline.append(event)
    
    # Sort by datetime
    timeline.sort(key=lambda x: x['datetime'])
    
    return timeline


def find_nearest_events(timeline: List[Dict[str, Any]], target_time: datetime.datetime, 
                        before_count: int = 5, after_count: int = 5) -> Dict[str, List[Dict[str, Any]]]:
    """
    Find events nearest to a target time in a timeline
    
    Args:
        timeline: Timeline of events
        target_time: Target datetime
        before_count: Number of events before target to include
        after_count: Number of events after target to include
        
    Returns:
        Dictionary with events before and after the target time
    """
    # Sort timeline by datetime
    sorted_timeline = sorted(timeline, key=lambda x: x['datetime'])
    
    # Find the position where target_time would be inserted
    position = 0
    while position < len(sorted_timeline) and sorted_timeline[position]['datetime'] < target_time:
        position += 1
    
    # Get events before and after
    events_before = sorted_timeline[max(0, position - before_count):position]
    events_after = sorted_timeline[position:min(len(sorted_timeline), position + after_count)]
    
    return {
        'before': events_before,
        'after': events_after,
        'target_time': format_datetime(target_time)
    }


def generate_timeline_report(timeline: List[Dict[str, Any]], 
                            start_time: Optional[datetime.datetime] = None,
                            end_time: Optional[datetime.datetime] = None,
                            fields: Optional[List[str]] = None) -> str:
    """
    Generate a formatted timeline report
    
    Args:
        timeline: Timeline of events
        start_time: Optional start time to filter events
        end_time: Optional end time to filter events
        fields: Optional list of field names to include
        
    Returns:
        Formatted timeline report
    """
    # Filter by time range if specified
    filtered_timeline = timeline
    
    if start_time:
        filtered_timeline = [event for event in filtered_timeline if event['datetime'] >= start_time]
    
    if end_time:
        filtered_timeline = [event for event in filtered_timeline if event['datetime'] <= end_time]
    
    # Filter by fields if specified
    if fields:
        filtered_timeline = [event for event in filtered_timeline if event['field'] in fields]
    
    # Sort by datetime
    filtered_timeline.sort(key=lambda x: x['datetime'])
    
    # Generate report
    report = "# Timeline Report\n\n"
    
    if start_time and end_time:
        report += f"Time range: {format_datetime(start_time)} to {format_datetime(end_time)}\n\n"
    elif start_time:
        report += f"Time range: From {format_datetime(start_time)}\n\n"
    elif end_time:
        report += f"Time range: Until {format_datetime(end_time)}\n\n"
    
    report += f"Total events: {len(filtered_timeline)}\n\n"
    
    if filtered_timeline:
        report += "| Time | Event | Type | Field |\n"
        report += "|------|-------|------|-------|\n"
        
        for event in filtered_timeline:
            report += f"| {event['formatted']} | {event['field']} | {event['type']} | {event['value']} |\n"
    else:
        report += "No events found in the specified time range.\n"
    
    return report
