# tools/advanced/reporting.py - Forensic reporting tools

import os
import json
import logging
import tempfile
import shutil
import re
import datetime
from typing import Dict, List, Optional, Any, Tuple, Union, BinaryIO, Callable

# Set up logging
logger = logging.getLogger(__name__)


class ForensicReportGenerator:
    """
    Generator for forensic analysis reports
    
    Creates standardized reports from forensic analysis data
    """
    
    # Report template formats
    FORMAT_MARKDOWN = 'markdown'
    FORMAT_HTML = 'html'
    FORMAT_JSON = 'json'
    
    # Report templates
    TEMPLATE_STANDARD = 'standard'
    TEMPLATE_TIMELINE = 'timeline'
    TEMPLATE_EXECUTIVE = 'executive'
    TEMPLATE_TECHNICAL = 'technical'
    
    def __init__(self, case_info: Optional[Dict[str, Any]] = None):
        """
        Initialize the report generator
        
        Args:
            case_info: Optional case information dictionary
        """
        self.case_info = case_info or {}
        
        # Default case information
        if 'case_number' not in self.case_info:
            self.case_info['case_number'] = 'CASE-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        
        if 'report_date' not in self.case_info:
            self.case_info['report_date'] = datetime.datetime.now().isoformat()
        
        if 'examiner' not in self.case_info:
            self.case_info['examiner'] = 'Unknown'
        
        if 'device_info' not in self.case_info:
            self.case_info['device_info'] = {
                'model': 'Unknown',
                'os_version': 'Unknown',
                'serial_number': 'Unknown'
            }
    
    def generate_report(self, data: Dict[str, Any], template: str = TEMPLATE_STANDARD, 
                       format: str = FORMAT_MARKDOWN, output_path: Optional[str] = None) -> str:
        """
        Generate a forensic report
        
        Args:
            data: Forensic data to include in the report
            template: Report template to use
            format: Output format
            output_path: Optional path to save the report
            
        Returns:
            Generated report content
        """
        logger.info(f"Generating {template} report in {format} format")
        
        # Select the appropriate template and format
        if template == self.TEMPLATE_TIMELINE:
            content = self._generate_timeline_report(data, format)
        elif template == self.TEMPLATE_EXECUTIVE:
            content = self._generate_executive_report(data, format)
        elif template == self.TEMPLATE_TECHNICAL:
            content = self._generate_technical_report(data, format)
        else:
            # Standard template
            content = self._generate_standard_report(data, format)
        
        # Save the report if output path is provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Report saved to {output_path}")
        
        return content
    
    def _generate_standard_report(self, data: Dict[str, Any], format: str) -> str:
        """
        Generate a standard forensic report
        
        Args:
            data: Forensic data
            format: Output format
            
        Returns:
            Report content
        """
        if format == self.FORMAT_MARKDOWN:
            return self._generate_standard_markdown(data)
        elif format == self.FORMAT_HTML:
            return self._generate_standard_html(data)
        elif format == self.FORMAT_JSON:
            return json.dumps({
                'case_info': self.case_info,
                'data': data,
                'report_type': 'standard'
            }, indent=2)
        else:
            logger.warning(f"Unsupported format: {format}, falling back to markdown")
            return self._generate_standard_markdown(data)
    
    def _generate_standard_markdown(self, data: Dict[str, Any]) -> str:
        """
        Generate a standard markdown report
        
        Args:
            data: Forensic data
            
        Returns:
            Markdown report
        """
        # Build the report content
        lines = []
        
        # Header
        lines.append('# iOS Forensic Analysis Report')
        lines.append('')
        
        # Case information
        lines.append('## Case Information')
        lines.append('')
        lines.append(f"**Case Number:** {self.case_info.get('case_number')}")
        lines.append(f"**Examiner:** {self.case_info.get('examiner')}")
        lines.append(f"**Report Date:** {self._format_datetime(self.case_info.get('report_date'))}")
        lines.append('')
        
        # Device information
        lines.append('## Device Information')
        lines.append('')
        device_info = self.case_info.get('device_info', {})
        lines.append(f"**Model:** {device_info.get('model', 'Unknown')}")
        lines.append(f"**iOS Version:** {device_info.get('os_version', 'Unknown')}")
        lines.append(f"**Serial Number:** {device_info.get('serial_number', 'Unknown')}")
        
        if 'imei' in device_info:
            lines.append(f"**IMEI:** {device_info.get('imei')}")
        
        if 'extraction_method' in self.case_info:
            lines.append(f"**Extraction Method:** {self.case_info.get('extraction_method')}")
        
        if 'extraction_date' in self.case_info:
            lines.append(f"**Extraction Date:** {self._format_datetime(self.case_info.get('extraction_date'))}")
        
        lines.append('')
        
        # Executive summary
        if 'executive_summary' in self.case_info:
            lines.append('## Executive Summary')
            lines.append('')
            lines.append(self.case_info.get('executive_summary'))
            lines.append('')
        
        # Key findings
        if 'key_findings' in data:
            lines.append('## Key Findings')
            lines.append('')
            
            findings = data.get('key_findings', [])
            for i, finding in enumerate(findings, 1):
                lines.append(f"{i}. {finding}")
            
            lines.append('')
        
        # Analysis sections
        self._add_analysis_sections(lines, data)
        
        # Timeline
        if 'timeline' in data:
            self._add_timeline_section(lines, data.get('timeline', []))
        
        # Conclusion
        if 'conclusion' in self.case_info:
            lines.append('## Conclusion')
            lines.append('')
            lines.append(self.case_info.get('conclusion'))
            lines.append('')
        
        # Appendices
        if 'appendices' in data:
            lines.append('## Appendices')
            lines.append('')
            
            appendices = data.get('appendices', {})
            for title, content in appendices.items():
                lines.append(f"### {title}")
                lines.append('')
                lines.append(content)
                lines.append('')
        
        return '\n'.join(lines)
    
    def _generate_standard_html(self, data: Dict[str, Any]) -> str:
        """
        Generate a standard HTML report
        
        Args:
            data: Forensic data
            
        Returns:
            HTML report
        """
        # Convert the markdown report to HTML
        markdown_report = self._generate_standard_markdown(data)
        
        # Simple markdown to HTML conversion for basic elements
        html_lines = []
        
        # HTML header
        html_lines.append('<!DOCTYPE html>')
        html_lines.append('<html lang="en">')
        html_lines.append('<head>')
        html_lines.append('    <meta charset="UTF-8">')
        html_lines.append('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_lines.append(f'    <title>iOS Forensic Report - {self.case_info.get("case_number")}</title>')
        html_lines.append('    <style>')
        html_lines.append('        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }')
        html_lines.append('        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }')
        html_lines.append('        h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; }')
        html_lines.append('        h3 { color: #2c3e50; }')
        html_lines.append('        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }')
        html_lines.append('        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }')
        html_lines.append('        th { background-color: #f2f2f2; }')
        html_lines.append('        tr:nth-child(even) { background-color: #f9f9f9; }')
        html_lines.append('        .timeline-item { margin-bottom: 10px; padding-left: 20px; border-left: 2px solid #3498db; }')
        html_lines.append('        .timeline-date { font-weight: bold; color: #3498db; }')
        html_lines.append('        .key-value { margin-bottom: 5px; }')
        html_lines.append('        .key { font-weight: bold; }')
        html_lines.append('    </style>')
        html_lines.append('</head>')
        html_lines.append('<body>')
        
        # Convert markdown to HTML
        in_code_block = False
        in_list = False
        
        for line in markdown_report.split('\n'):
            # Headers
            if line.startswith('# '):
                html_lines.append(f'<h1>{line[2:]}</h1>')
            elif line.startswith('## '):
                html_lines.append(f'<h2>{line[3:]}</h2>')
            elif line.startswith('### '):
                html_lines.append(f'<h3>{line[4:]}</h3>')
            # Lists
            elif line.startswith('- '):
                if not in_list:
                    html_lines.append('<ul>')
                    in_list = True
                html_lines.append(f'<li>{line[2:]}</li>')
            elif line.startswith('1. ') or line.startswith('* '):
                if not in_list:
                    html_lines.append('<ul>')
                    in_list = True
                html_lines.append(f'<li>{line[2:]}</li>')
            # Code blocks
            elif line.startswith('```'):
                if in_code_block:
                    html_lines.append('</code></pre>')
                    in_code_block = False
                else:
                    html_lines.append('<pre><code>')
                    in_code_block = True
            # Bold text
            elif '**' in line:
                line = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', line)
                html_lines.append(f'<p>{line}</p>')
            # Empty line
            elif line.strip() == '':
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                else:
                    html_lines.append('<br>')
            # Regular paragraph
            else:
                html_lines.append(f'<p>{line}</p>')
        
        # Close any open tags
        if in_list:
            html_lines.append('</ul>')
        
        if in_code_block:
            html_lines.append('</code></pre>')
        
        # HTML footer
        html_lines.append('</body>')
        html_lines.append('</html>')
        
        return '\n'.join(html_lines)
    
    def _generate_timeline_report(self, data: Dict[str, Any], format: str) -> str:
        """
        Generate a timeline-focused report
        
        Args:
            data: Forensic data
            format: Output format
            
        Returns:
            Report content
        """
        if 'timeline' not in data:
            logger.warning("No timeline data provided for timeline report")
            # Fall back to standard report
            return self._generate_standard_report(data, format)
        
        timeline_data = data.get('timeline', [])
        
        if format == self.FORMAT_MARKDOWN:
            return self._generate_timeline_markdown(timeline_data)
        elif format == self.FORMAT_HTML:
            return self._generate_timeline_html(timeline_data)
        elif format == self.FORMAT_JSON:
            return json.dumps({
                'case_info': self.case_info,
                'timeline': timeline_data,
                'report_type': 'timeline'
            }, indent=2)
        else:
            logger.warning(f"Unsupported format: {format}, falling back to markdown")
            return self._generate_timeline_markdown(timeline_data)
    
    def _generate_timeline_markdown(self, timeline_data: List[Dict[str, Any]]) -> str:
        """
        Generate a timeline report in markdown format
        
        Args:
            timeline_data: Timeline entries
            
        Returns:
            Markdown report
        """
        lines = []
        
        # Header
        lines.append('# iOS Forensic Timeline Report')
        lines.append('')
        
        # Case information
        lines.append('## Case Information')
        lines.append('')
        lines.append(f"**Case Number:** {self.case_info.get('case_number')}")
        lines.append(f"**Examiner:** {self.case_info.get('examiner')}")
        lines.append(f"**Report Date:** {self._format_datetime(self.case_info.get('report_date'))}")
        lines.append('')
        
        # Device information
        lines.append('## Device Information')
        lines.append('')
        device_info = self.case_info.get('device_info', {})
        lines.append(f"**Model:** {device_info.get('model', 'Unknown')}")
        lines.append(f"**iOS Version:** {device_info.get('os_version', 'Unknown')}")
        lines.append('')
        
        # Timeline statistics
        lines.append('## Timeline Statistics')
        lines.append('')
        lines.append(f"**Total Events:** {len(timeline_data)}")
        
        if timeline_data:
            # Find date range
            try:
                dates = []
                for entry in timeline_data:
                    if 'timestamp' in entry:
                        dates.append(entry['timestamp'])
                
                if dates:
                    lines.append(f"**Date Range:** {min(dates)} to {max(dates)}")
            except Exception:
                pass
            
            # Count event types
            event_types = {}
            for entry in timeline_data:
                entry_type = entry.get('type', 'unknown')
                event_types[entry_type] = event_types.get(entry_type, 0) + 1
            
            lines.append('')
            lines.append('**Event Types:**')
            for event_type, count in event_types.items():
                lines.append(f"- {event_type}: {count}")
        
        lines.append('')
        
        # Timeline
        lines.append('## Timeline')
        lines.append('')
        
        # Sort by timestamp
        sorted_timeline = sorted(timeline_data, key=lambda x: x.get('timestamp', ''))
        
        # Group by date
        current_date = None
        for entry in sorted_timeline:
            timestamp = entry.get('timestamp', '')
            
            # Extract date part
            date_part = timestamp.split('T')[0] if 'T' in timestamp else timestamp
            
            # Add date header if changed
            if date_part != current_date:
                current_date = date_part
                lines.append(f"### {date_part}")
                lines.append('')
            
            # Format time part
            time_part = timestamp.split('T')[1] if 'T' in timestamp else ''
            if time_part:
                time_part = time_part.split('.')[0] if '.' in time_part else time_part
                time_part = time_part.split('+')[0] if '+' in time_part else time_part
                time_part = time_part.split('Z')[0] if 'Z' in time_part else time_part
            
            # Add entry
            entry_type = entry.get('type', 'unknown')
            description = entry.get('description', 'No description')
            
            lines.append(f"**{time_part}** - {entry_type}: {description}")
            
            # Add location if available
            if 'latitude' in entry and 'longitude' in entry:
                lat = entry.get('latitude')
                lon = entry.get('longitude')
                lines.append(f"Location: {lat}, {lon}")
            
            # Add duration if available
            if 'duration_formatted' in entry:
                lines.append(f"Duration: {entry.get('duration_formatted')}")
            
            lines.append('')
        
        return '\n'.join(lines)
    
    def _generate_timeline_html(self, timeline_data: List[Dict[str, Any]]) -> str:
        """
        Generate a timeline report in HTML format
        
        Args:
            timeline_data: Timeline entries
            
        Returns:
            HTML report
        """
        # Convert the markdown timeline report to HTML
        markdown_report = self._generate_timeline_markdown(timeline_data)
        
        # Add HTML template with timeline styling
        html_lines = []
        
        # HTML header
        html_lines.append('<!DOCTYPE html>')
        html_lines.append('<html lang="en">')
        html_lines.append('<head>')
        html_lines.append('    <meta charset="UTF-8">')
        html_lines.append('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_lines.append(f'    <title>iOS Forensic Timeline - {self.case_info.get("case_number")}</title>')
        html_lines.append('    <style>')
        html_lines.append('        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }')
        html_lines.append('        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }')
        html_lines.append('        h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; }')
        html_lines.append('        h3 { color: #2c3e50; margin-top: 30px; border-bottom: 1px dashed #bdc3c7; }')
        html_lines.append('        .timeline { position: relative; max-width: 1200px; margin: 0 auto; }')
        html_lines.append('        .timeline::after { content: ""; position: absolute; width: 2px; background-color: #3498db; top: 0; bottom: 0; left: 50px; }')
        html_lines.append('        .timeline-item { padding: 10px 40px 10px 70px; position: relative; background-color: inherit; width: 100%; box-sizing: border-box; }')
        html_lines.append('        .timeline-item::after { content: ""; position: absolute; width: 12px; height: 12px; background-color: white; border: 2px solid #3498db; border-radius: 50%; z-index: 1; left: 44px; top: 15px; }')
        html_lines.append('        .timeline-date { font-weight: bold; color: #3498db; }')
        html_lines.append('        .timeline-type { color: #7f8c8d; font-style: italic; }')
        html_lines.append('        .timeline-description { margin-top: 5px; }')
        html_lines.append('        .timeline-location { color: #7f8c8d; margin-top: 5px; font-size: 0.9em; }')
        html_lines.append('        .timeline-duration { color: #7f8c8d; font-size: 0.9em; }')
        html_lines.append('    </style>')
        html_lines.append('</head>')
        html_lines.append('<body>')
        
        # Custom HTML timeline instead of converting from markdown
        html_lines.append('<h1>iOS Forensic Timeline Report</h1>')
        
        # Case information
        html_lines.append('<h2>Case Information</h2>')
        html_lines.append('<div class="case-info">')
        html_lines.append(f'<p><strong>Case Number:</strong> {self.case_info.get("case_number")}</p>')
        html_lines.append(f'<p><strong>Examiner:</strong> {self.case_info.get("examiner")}</p>')
        html_lines.append(f'<p><strong>Report Date:</strong> {self._format_datetime(self.case_info.get("report_date"))}</p>')
        html_lines.append('</div>')
        
        # Device information
        html_lines.append('<h2>Device Information</h2>')
        html_lines.append('<div class="device-info">')
        device_info = self.case_info.get('device_info', {})
        html_lines.append(f'<p><strong>Model:</strong> {device_info.get("model", "Unknown")}</p>')
        html_lines.append(f'<p><strong>iOS Version:</strong> {device_info.get("os_version", "Unknown")}</p>')
        html_lines.append('</div>')
        
        # Timeline statistics
        html_lines.append('<h2>Timeline Statistics</h2>')
        html_lines.append('<div class="timeline-stats">')
        html_lines.append(f'<p><strong>Total Events:</strong> {len(timeline_data)}</p>')
        
        if timeline_data:
            # Find date range
            try:
                dates = []
                for entry in timeline_data:
                    if 'timestamp' in entry:
                        dates.append(entry['timestamp'])
                
                if dates:
                    html_lines.append(f'<p><strong>Date Range:</strong> {min(dates)} to {max(dates)}</p>')
            except Exception:
                pass
            
            # Count event types
            event_types = {}
            for entry in timeline_data:
                entry_type = entry.get('type', 'unknown')
                event_types[entry_type] = event_types.get(entry_type, 0) + 1
            
            html_lines.append('<p><strong>Event Types:</strong></p>')
            html_lines.append('<ul>')
            for event_type, count in event_types.items():
                html_lines.append(f'<li>{event_type}: {count}</li>')
            html_lines.append('</ul>')
        
        html_lines.append('</div>')
        
        # Timeline
        html_lines.append('<h2>Timeline</h2>')
        
        # Sort by timestamp
        sorted_timeline = sorted(timeline_data, key=lambda x: x.get('timestamp', ''))
        
        # Group by date
        html_lines.append('<div class="timeline">')
        current_date = None
        
        for entry in sorted_timeline:
            timestamp = entry.get('timestamp', '')
            
            # Extract date part
            date_part = timestamp.split('T')[0] if 'T' in timestamp else timestamp
            
            # Add date header if changed
            if date_part != current_date:
                if current_date is not None:
                    # Close previous date section
                    html_lines.append('</div>')
                
                current_date = date_part
                html_lines.append(f'<h3>{date_part}</h3>')
                html_lines.append('<div class="timeline-date-group">')
            
            # Format time part
            time_part = timestamp.split('T')[1] if 'T' in timestamp else ''
            if time_part:
                time_part = time_part.split('.')[0] if '.' in time_part else time_part
                time_part = time_part.split('+')[0] if '+' in time_part else time_part
                time_part = time_part.split('Z')[0] if 'Z' in time_part else time_part
            
            # Add entry
            entry_type = entry.get('type', 'unknown')
            description = entry.get('description', 'No description')
            
            html_lines.append('<div class="timeline-item">')
            html_lines.append(f'<div class="timeline-date">{time_part}</div>')
            html_lines.append(f'<div class="timeline-type">{entry_type}</div>')
            html_lines.append(f'<div class="timeline-description">{description}</div>')
            
            # Add location if available
            if 'latitude' in entry and 'longitude' in entry:
                lat = entry.get('latitude')
                lon = entry.get('longitude')
                html_lines.append(f'<div class="timeline-location">Location: {lat}, {lon}</div>')
            
            # Add duration if available
            if 'duration_formatted' in entry:
                html_lines.append(f'<div class="timeline-duration">Duration: {entry.get("duration_formatted")}</div>')
            
            html_lines.append('</div>')
        
        # Close last date section
        if current_date is not None:
            html_lines.append('</div>')
        
        html_lines.append('</div>')  # Close timeline
        
        # HTML footer
        html_lines.append('</body>')
        html_lines.append('</html>')
        
        return '\n'.join(html_lines)
    
    def _generate_executive_report(self, data: Dict[str, Any], format: str) -> str:
        """
        Generate an executive summary report
        
        Args:
            data: Forensic data
            format: Output format
            
        Returns:
            Report content
        """
        if format == self.FORMAT_MARKDOWN:
            return self._generate_executive_markdown(data)
        elif format == self.FORMAT_HTML:
            return self._generate_executive_html(data)
        elif format == self.FORMAT_JSON:
            return json.dumps({
                'case_info': self.case_info,
                'data': {
                    'executive_summary': data.get('executive_summary', ''),
                    'key_findings': data.get('key_findings', []),
                    'conclusions': data.get('conclusions', '')
                },
                'report_type': 'executive'
            }, indent=2)
        else:
            logger.warning(f"Unsupported format: {format}, falling back to markdown")
            return self._generate_executive_markdown(data)
    
    def _generate_executive_markdown(self, data: Dict[str, Any]) -> str:
        """
        Generate an executive report in markdown format
        
        Args:
            data: Forensic data
            
        Returns:
            Markdown report
        """
        lines = []
        
        # Header
        lines.append('# iOS Forensic Analysis - Executive Summary')
        lines.append('')
        
        # Case information
        lines.append('## Case Information')
        lines.append('')
        lines.append(f"**Case Number:** {self.case_info.get('case_number')}")
        lines.append(f"**Examiner:** {self.case_info.get('examiner')}")
        lines.append(f"**Report Date:** {self._format_datetime(self.case_info.get('report_date'))}")
        lines.append('')
        
        # Device information
        lines.append('## Device Information')
        lines.append('')
        device_info = self.case_info.get('device_info', {})
        lines.append(f"**Model:** {device_info.get('model', 'Unknown')}")
        lines.append(f"**iOS Version:** {device_info.get('os_version', 'Unknown')}")
        lines.append(f"**Serial Number:** {device_info.get('serial_number', 'Unknown')}")
        
        if 'imei' in device_info:
            lines.append(f"**IMEI:** {device_info.get('imei')}")
        
        if 'extraction_method' in self.case_info:
            lines.append(f"**Extraction Method:** {self.case_info.get('extraction_method')}")
        
        lines.append('')
        
        # Executive summary
        lines.append('## Executive Summary')
        lines.append('')
        
        if 'executive_summary' in data:
            lines.append(data.get('executive_summary'))
        else:
            lines.append("No executive summary provided.")
        
        lines.append('')
        
        # Key findings
        lines.append('## Key Findings')
        lines.append('')
        
        if 'key_findings' in data and data.get('key_findings'):
            findings = data.get('key_findings', [])
            for i, finding in enumerate(findings, 1):
                lines.append(f"{i}. {finding}")
        else:
            lines.append("No key findings provided.")
        
        lines.append('')
        
        # Conclusion
        if 'conclusions' in data:
            lines.append('## Conclusions')
            lines.append('')
            lines.append(data.get('conclusions'))
            lines.append('')
        
        # Recommendations (if available)
        if 'recommendations' in data:
            lines.append('## Recommendations')
            lines.append('')
            
            recommendations = data.get('recommendations', [])
            for i, recommendation in enumerate(recommendations, 1):
                lines.append(f"{i}. {recommendation}")
            
            lines.append('')
        
        return '\n'.join(lines)
    
    def _generate_executive_html(self, data: Dict[str, Any]) -> str:
        """
        Generate an executive report in HTML format
        
        Args:
            data: Forensic data
            
        Returns:
            HTML report
        """
        # Convert markdown to HTML
        markdown_report = self._generate_executive_markdown(data)
        
        # Simple HTML template
        html_lines = []
        
        # HTML header
        html_lines.append('<!DOCTYPE html>')
        html_lines.append('<html lang="en">')
        html_lines.append('<head>')
        html_lines.append('    <meta charset="UTF-8">')
        html_lines.append('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_lines.append(f'    <title>iOS Forensic Analysis - Executive Summary - {self.case_info.get("case_number")}</title>')
        html_lines.append('    <style>')
        html_lines.append('        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 40px; max-width: 800px; margin: 0 auto; }')
        html_lines.append('        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }')
        html_lines.append('        h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }')
        html_lines.append('        .key-value { margin-bottom: 10px; }')
        html_lines.append('        .key { font-weight: bold; color: #2c3e50; }')
        html_lines.append('        ol { padding-left: 20px; }')
        html_lines.append('        li { margin-bottom: 10px; }')
        html_lines.append('        .summary, .conclusions { line-height: 1.8; text-align: justify; }')
        html_lines.append('    </style>')
        html_lines.append('</head>')
        html_lines.append('<body>')
        
        # Convert markdown to HTML
        in_list = False
        
        for line in markdown_report.split('\n'):
            # Headers
            if line.startswith('# '):
                html_lines.append(f'<h1>{line[2:]}</h1>')
            elif line.startswith('## '):
                html_lines.append(f'<h2>{line[3:]}</h2>')
            # Lists
            elif re.match(r'^\d+\. ', line):
                if not in_list:
                    html_lines.append('<ol>')
                    in_list = True
                
                item = re.sub(r'^\d+\. ', '', line)
                html_lines.append(f'<li>{item}</li>')
            # Bold text
            elif '**' in line:
                if '**' in line and ':' in line:
                    # This is likely a key-value pair
                    parts = line.split(':', 1)
                    key = parts[0].replace('**', '')
                    value = parts[1].strip() if len(parts) > 1 else ''
                    
                    html_lines.append(f'<div class="key-value"><span class="key">{key}:</span> {value}</div>')
                else:
                    line = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', line)
                    html_lines.append(f'<p>{line}</p>')
            # Empty line
            elif line.strip() == '':
                if in_list:
                    html_lines.append('</ol>')
                    in_list = False
                else:
                    html_lines.append('<br>')
            # Regular paragraph
            else:
                container_class = ''
                if 'Executive Summary' in html_lines[-1]:
                    container_class = ' class="summary"'
                elif 'Conclusions' in html_lines[-1]:
                    container_class = ' class="conclusions"'
                
                html_lines.append(f'<p{container_class}>{line}</p>')
        
        # Close any open tags
        if in_list:
            html_lines.append('</ol>')
        
        # HTML footer
        html_lines.append('</body>')
        html_lines.append('</html>')
        
        return '\n'.join(html_lines)
    
    def _generate_technical_report(self, data: Dict[str, Any], format: str) -> str:
        """
        Generate a technical forensic report
        
        Args:
            data: Forensic data
            format: Output format
            
        Returns:
            Report content
        """
        if format == self.FORMAT_MARKDOWN:
            return self._generate_technical_markdown(data)
        elif format == self.FORMAT_HTML:
            return self._generate_technical_html(data)
        elif format == self.FORMAT_JSON:
            return json.dumps({
                'case_info': self.case_info,
                'data': data,
                'report_type': 'technical'
            }, indent=2)
        else:
            logger.warning(f"Unsupported format: {format}, falling back to markdown")
            return self._generate_technical_markdown(data)
    
    def _generate_technical_markdown(self, data: Dict[str, Any]) -> str:
        """
        Generate a technical report in markdown format
        
        Args:
            data: Forensic data
            
        Returns:
            Markdown report
        """
        lines = []
        
        # Header
        lines.append('# iOS Forensic Analysis - Technical Report')
        lines.append('')
        
        # Case information
        lines.append('## Case Information')
        lines.append('')
        lines.append(f"**Case Number:** {self.case_info.get('case_number')}")
        lines.append(f"**Examiner:** {self.case_info.get('examiner')}")
        lines.append(f"**Report Date:** {self._format_datetime(self.case_info.get('report_date'))}")
        lines.append('')
        
        # Device information
        lines.append('## Device Information')
        lines.append('')
        device_info = self.case_info.get('device_info', {})
        
        # Create a table for device info
        lines.append('| Property | Value |')
        lines.append('|----------|-------|')
        lines.append(f"| Model | {device_info.get('model', 'Unknown')} |")
        lines.append(f"| iOS Version | {device_info.get('os_version', 'Unknown')} |")
        lines.append(f"| Serial Number | {device_info.get('serial_number', 'Unknown')} |")
        
        if 'imei' in device_info:
            lines.append(f"| IMEI | {device_info.get('imei')} |")
        
        if 'udid' in device_info:
            lines.append(f"| UDID | {device_info.get('udid')} |")
        
        if 'capacity' in device_info:
            lines.append(f"| Capacity | {device_info.get('capacity')} |")
        
        lines.append('')
        
        # Extraction information
        if 'extraction_info' in data:
            lines.append('## Extraction Information')
            lines.append('')
            
            extraction_info = data.get('extraction_info', {})
            
            lines.append('| Property | Value |')
            lines.append('|----------|-------|')
            lines.append(f"| Method | {extraction_info.get('method', 'Unknown')} |")
            lines.append(f"| Tool | {extraction_info.get('tool', 'Unknown')} |")
            lines.append(f"| Date | {self._format_datetime(extraction_info.get('date', ''))} |")
            
            if 'hash' in extraction_info:
                lines.append(f"| Hash | {extraction_info.get('hash')} |")
            
            lines.append('')
        
        # Analysis methodology
        if 'methodology' in data:
            lines.append('## Analysis Methodology')
            lines.append('')
            lines.append(data.get('methodology', ''))
            lines.append('')
        
        # Analysis sections with detailed technical content
        self._add_technical_sections(lines, data)
        
        # Technical findings
        if 'findings' in data:
            lines.append('## Technical Findings')
            lines.append('')
            
            findings = data.get('findings', [])
            for i, finding in enumerate(findings, 1):
                finding_title = finding.get('title', f'Finding {i}')
                finding_description = finding.get('description', '')
                finding_evidence = finding.get('evidence', [])
                
                lines.append(f"### {finding_title}")
                lines.append('')
                lines.append(finding_description)
                lines.append('')
                
                if finding_evidence:
                    lines.append('**Evidence:**')
                    lines.append('')
                    
                    for evidence in finding_evidence:
                        lines.append(f"- {evidence}")
                    
                    lines.append('')
        
        # Technical timeline
        if 'timeline' in data:
            self._add_technical_timeline(lines, data.get('timeline', []))
        
        # Appendices
        if 'appendices' in data:
            lines.append('## Appendices')
            lines.append('')
            
            appendices = data.get('appendices', {})
            for title, content in appendices.items():
                lines.append(f"### {title}")
                lines.append('')
                lines.append(content)
                lines.append('')
        
        # References
        if 'references' in data:
            lines.append('## References')
            lines.append('')
            
            references = data.get('references', [])
            for i, reference in enumerate(references, 1):
                lines.append(f"{i}. {reference}")
            
            lines.append('')
        
        return '\n'.join(lines)
    
    def _generate_technical_html(self, data: Dict[str, Any]) -> str:
        """
        Generate a technical report in HTML format
        
        Args:
            data: Forensic data
            
        Returns:
            HTML report
        """
        # Convert markdown to HTML
        markdown_report = self._generate_technical_markdown(data)
        
        # Simple HTML template
        html_lines = []
        
        # HTML header
        html_lines.append('<!DOCTYPE html>')
        html_lines.append('<html lang="en">')
        html_lines.append('<head>')
        html_lines.append('    <meta charset="UTF-8">')
        html_lines.append('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_lines.append(f'    <title>iOS Forensic Analysis - Technical Report - {self.case_info.get("case_number")}</title>')
        html_lines.append('    <style>')
        html_lines.append('        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 40px; }')
        html_lines.append('        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }')
        html_lines.append('        h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }')
        html_lines.append('        h3 { color: #2c3e50; }')
        html_lines.append('        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }')
        html_lines.append('        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }')
        html_lines.append('        th { background-color: #f2f2f2; }')
        html_lines.append('        tr:nth-child(even) { background-color: #f9f9f9; }')
        html_lines.append('        code { background-color: #f8f8f8; padding: 2px 4px; border-radius: 3px; font-family: monospace; }')
        html_lines.append('        pre { background-color: #f8f8f8; padding: 10px; border-radius: 5px; overflow-x: auto; font-family: monospace; }')
        html_lines.append('        .evidence-item { margin-left: 20px; padding-left: 10px; border-left: 3px solid #3498db; margin-bottom: 10px; }')
        html_lines.append('        .technical-data { font-family: monospace; white-space: pre-wrap; }')
        html_lines.append('    </style>')
        html_lines.append('</head>')
        html_lines.append('<body>')
        
        # Convert markdown to HTML
        in_code_block = False
        in_table = False
        table_rows = []
        
        for line in markdown_report.split('\n'):
            # Headers
            if line.startswith('# '):
                html_lines.append(f'<h1>{line[2:]}</h1>')
            elif line.startswith('## '):
                html_lines.append(f'<h2>{line[3:]}</h2>')
            elif line.startswith('### '):
                html_lines.append(f'<h3>{line[4:]}</h3>')
            # Tables
            elif line.startswith('|') and line.endswith('|'):
                if not in_table:
                    in_table = True
                    table_rows = []
                
                table_rows.append(line)
            # End of table
            elif in_table and line.strip() == '':
                if table_rows:
                    html_lines.append('<table>')
                    
                    # Process table rows
                    is_header_row = True
                    is_separator_row = False
                    
                    for i, row in enumerate(table_rows):
                        cells = [cell.strip() for cell in row.split('|')[1:-1]]
                        
                        if i == 1 and all('-' in cell for cell in cells):
                            is_separator_row = True
                            continue
                        
                        if is_header_row and not is_separator_row:
                            html_lines.append('<tr>')
                            for cell in cells:
                                html_lines.append(f'<th>{cell}</th>')
                            html_lines.append('</tr>')
                            is_header_row = False
                        else:
                            html_lines.append('<tr>')
                            for cell in cells:
                                html_lines.append(f'<td>{cell}</td>')
                            html_lines.append('</tr>')
                    
                    html_lines.append('</table>')
                
                in_table = False
                table_rows = []
            # Code blocks
            elif line.startswith('```'):
                if in_code_block:
                    html_lines.append('</code></pre>')
                    in_code_block = False
                else:
                    lang = line[3:].strip()
                    html_lines.append(f'<pre><code class="language-{lang}">')
                    in_code_block = True
            # Lists
            elif line.startswith('- '):
                html_lines.append(f'<div class="evidence-item">{line[2:]}</div>')
            # Bold text
            elif '**' in line:
                line = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', line)
                html_lines.append(f'<p>{line}</p>')
            # Empty line
            elif line.strip() == '' and not in_table:
                html_lines.append('<br>')
            # Regular paragraph
            elif not in_table and not in_code_block:
                html_lines.append(f'<p>{line}</p>')
            # Inside code block
            elif in_code_block:
                html_lines.append(line)
        
        # Close any open tags
        if in_table:
            html_lines.append('</table>')
        
        if in_code_block:
            html_lines.append('</code></pre>')
        
        # HTML footer
        html_lines.append('</body>')
        html_lines.append('</html>')
        
        return '\n'.join(html_lines)
    
    def _add_analysis_sections(self, lines: List[str], data: Dict[str, Any]) -> None:
        """
        Add analysis sections to the report
        
        Args:
            lines: List of report lines to append to
            data: Forensic data
        """
        # Check for analysis sections
        if 'analysis' in data and isinstance(data['analysis'], dict):
            analysis = data['analysis']
            
            for section_title, section_data in analysis.items():
                lines.append(f"## {section_title}")
                lines.append('')
                
                if isinstance(section_data, str):
                    # Simple text section
                    lines.append(section_data)
                elif isinstance(section_data, dict):
                    # Complex section with subsections
                    if 'summary' in section_data:
                        lines.append(section_data['summary'])
                        lines.append('')
                    
                    if 'findings' in section_data:
                        findings = section_data['findings']
                        if isinstance(findings, list):
                            for finding in findings:
                                if isinstance(finding, str):
                                    lines.append(f"- {finding}")
                                elif isinstance(finding, dict) and 'description' in finding:
                                    lines.append(f"- {finding['description']}")
                            
                            lines.append('')
                        elif isinstance(findings, dict):
                            for key, value in findings.items():
                                lines.append(f"### {key}")
                                lines.append('')
                                lines.append(value)
                                lines.append('')
                    
                    if 'data' in section_data:
                        data_content = section_data['data']
                        if isinstance(data_content, list):
                            for item in data_content:
                                if isinstance(item, dict) and 'label' in item and 'value' in item:
                                    lines.append(f"**{item['label']}:** {item['value']}")
                            
                            lines.append('')
                        elif isinstance(data_content, dict):
                            lines.append('| Property | Value |')
                            lines.append('|----------|-------|')
                            
                            for key, value in data_content.items():
                                if isinstance(value, (str, int, float, bool)):
                                    lines.append(f"| {key} | {value} |")
                            
                            lines.append('')
                
                elif isinstance(section_data, list):
                    # List of items
                    for item in section_data:
                        if isinstance(item, str):
                            lines.append(f"- {item}")
                        elif isinstance(item, dict) and 'description' in item:
                            lines.append(f"- {item['description']}")
                    
                    lines.append('')
    
    def _add_timeline_section(self, lines: List[str], timeline_data: List[Dict[str, Any]]) -> None:
        """
        Add timeline section to the report
        
        Args:
            lines: List of report lines to append to
            timeline_data: Timeline entries
        """
        if not timeline_data:
            return
        
        lines.append('## Timeline')
        lines.append('')
        
        # Sort timeline entries by timestamp
        sorted_timeline = sorted(timeline_data, key=lambda x: x.get('timestamp', ''))
        
        # Group by date
        current_date = None
        for entry in sorted_timeline:
            timestamp = entry.get('timestamp', '')
            
            # Extract date part
            date_part = timestamp.split('T')[0] if 'T' in timestamp else timestamp
            
            # Add date header if changed
            if date_part != current_date:
                current_date = date_part
                lines.append(f"### {date_part}")
                lines.append('')
            
            # Format time part
            time_part = timestamp.split('T')[1] if 'T' in timestamp else ''
            if time_part:
                time_part = time_part.split('.')[0] if '.' in time_part else time_part
                time_part = time_part.split('+')[0] if '+' in time_part else time_part
                time_part = time_part.split('Z')[0] if 'Z' in time_part else time_part
            
            # Add entry
            entry_type = entry.get('type', 'unknown')
            description = entry.get('description', 'No description')
            
            lines.append(f"**{time_part}** - {entry_type}: {description}")
            
            # Add location if available
            if 'latitude' in entry and 'longitude' in entry:
                lat = entry.get('latitude')
                lon = entry.get('longitude')
                lines.append(f"Location: {lat}, {lon}")
            
            # Add duration if available
            if 'duration_formatted' in entry:
                lines.append(f"Duration: {entry.get('duration_formatted')}")
            
            lines.append('')
    
    def _add_technical_sections(self, lines: List[str], data: Dict[str, Any]) -> None:
        """
        Add technical analysis sections to the report
        
        Args:
            lines: List of report lines to append to
            data: Forensic data
        """
        # Add technical analysis sections
        if 'technical_analysis' in data and isinstance(data['technical_analysis'], dict):
            technical_analysis = data['technical_analysis']
            
            for section_title, section_data in technical_analysis.items():
                lines.append(f"## {section_title}")
                lines.append('')
                
                if isinstance(section_data, str):
                    # Simple text section
                    lines.append(section_data)
                    lines.append('')
                elif isinstance(section_data, dict):
                    # Complex section with subsections
                    if 'description' in section_data:
                        lines.append(section_data['description'])
                        lines.append('')
                    
                    if 'technical_details' in section_data:
                        tech_details = section_data['technical_details']
                        
                        if isinstance(tech_details, str):
                            lines.append('```')
                            lines.append(tech_details)
                            lines.append('```')
                        elif isinstance(tech_details, dict):
                            lines.append('```json')
                            lines.append(json.dumps(tech_details, indent=2))
                            lines.append('```')
                        elif isinstance(tech_details, list):
                            for detail in tech_details:
                                if isinstance(detail, dict) and 'key' in detail and 'value' in detail:
                                    lines.append(f"**{detail['key']}:** {detail['value']}")
                        
                        lines.append('')
                    
                    if 'artifacts' in section_data:
                        artifacts = section_data['artifacts']
                        lines.append('### Artifacts')
                        lines.append('')
                        
                        for artifact in artifacts:
                            if isinstance(artifact, dict):
                                if 'path' in artifact:
                                    lines.append(f"- **Path:** {artifact['path']}")
                                if 'description' in artifact:
                                    lines.append(f"  **Description:** {artifact['description']}")
                                if 'hash' in artifact:
                                    lines.append(f"  **Hash:** {artifact['hash']}")
                                lines.append('')
                            elif isinstance(artifact, str):
                                lines.append(f"- {artifact}")
                        
                        lines.append('')
                
                elif isinstance(section_data, list):
                    # List of items
                    for item in section_data:
                        if isinstance(item, str):
                            lines.append(f"- {item}")
                        elif isinstance(item, dict):
                            if 'title' in item and 'content' in item:
                                lines.append(f"### {item['title']}")
                                lines.append('')
                                lines.append(item['content'])
                                lines.append('')
                            elif 'description' in item:
                                lines.append(f"- {item['description']}")
                    
                    lines.append('')
    
    def _add_technical_timeline(self, lines: List[str], timeline_data: List[Dict[str, Any]]) -> None:
        """
        Add technical timeline section to the report
        
        Args:
            lines: List of report lines to append to
            timeline_data: Timeline entries
        """
        if not timeline_data:
            return
        
        lines.append('## Technical Timeline')
        lines.append('')
        
        # Sort timeline entries by timestamp
        sorted_timeline = sorted(timeline_data, key=lambda x: x.get('timestamp', ''))
        
        # Create a table for the timeline
        lines.append('| Timestamp | Type | Description | Technical Details |')
        lines.append('|-----------|------|-------------|-------------------|')
        
        for entry in sorted_timeline:
            timestamp = entry.get('timestamp', '')
            entry_type = entry.get('type', 'unknown')
            description = entry.get('description', 'No description')
            
            # Format technical details
            tech_details = ''
            if 'technical_details' in entry:
                if isinstance(entry['technical_details'], dict):
                    details = []
                    for key, value in entry['technical_details'].items():
                        details.append(f"{key}: {value}")
                    tech_details = '<br>'.join(details)
                elif isinstance(entry['technical_details'], str):
                    tech_details = entry['technical_details']
            
            lines.append(f"| {timestamp} | {entry_type} | {description} | {tech_details} |")
        
        lines.append('')
    
    def _format_datetime(self, timestamp: Union[str, datetime.datetime, None]) -> str:
        """
        Format a datetime object or string as a readable string
        
        Args:
            timestamp: Datetime object, ISO format string, or None
            
        Returns:
            Formatted datetime string
        """
        if timestamp is None:
            return 'Unknown'
        
        if isinstance(timestamp, datetime.datetime):
            return timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        if isinstance(timestamp, str):
            try:
                dt = datetime.datetime.fromisoformat(timestamp)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                return timestamp
        
        return str(timestamp)


def generate_report(data: Dict[str, Any], case_info: Dict[str, Any] = None, 
                   template: str = 'standard', format: str = 'markdown',
                   output_path: Optional[str] = None) -> str:
    """
    Generate a forensic report
    
    Args:
        data: Forensic data
        case_info: Case information
        template: Report template ('standard', 'timeline', 'executive', 'technical')
        format: Output format ('markdown', 'html', 'json')
        output_path: Path to save the report
        
    Returns:
        Generated report content
    """
    logger.info(f"Generating {template} report in {format} format")
    
    generator = ForensicReportGenerator(case_info)
    return generator.generate_report(data, template, format, output_path)


def generate_timeline_report(timeline_data: List[Dict[str, Any]], case_info: Dict[str, Any] = None,
                           format: str = 'markdown', output_path: Optional[str] = None) -> str:
    """
    Generate a timeline report
    
    Args:
        timeline_data: Timeline entries
        case_info: Case information
        format: Output format ('markdown', 'html', 'json')
        output_path: Path to save the report
        
    Returns:
        Generated report content
    """
    logger.info(f"Generating timeline report in {format} format")
    
    generator = ForensicReportGenerator(case_info)
    return generator.generate_report({'timeline': timeline_data}, 'timeline', format, output_path)


def generate_technical_report(technical_data: Dict[str, Any], case_info: Dict[str, Any] = None,
                            format: str = 'markdown', output_path: Optional[str] = None) -> str:
    """
    Generate a technical report
    
    Args:
        technical_data: Technical forensic data
        case_info: Case information
        format: Output format ('markdown', 'html', 'json')
        output_path: Path to save the report
        
    Returns:
        Generated report content
    """
    logger.info(f"Generating technical report in {format} format")
    
    generator = ForensicReportGenerator(case_info)
    return generator.generate_report(technical_data, 'technical', format, output_path)


def generate_executive_report(key_findings: List[str], executive_summary: str = None,
                            conclusions: str = None, case_info: Dict[str, Any] = None,
                            format: str = 'markdown', output_path: Optional[str] = None) -> str:
    """
    Generate an executive summary report
    
    Args:
        key_findings: List of key findings
        executive_summary: Executive summary text
        conclusions: Conclusions text
        case_info: Case information
        format: Output format ('markdown', 'html', 'json')
        output_path: Path to save the report
        
    Returns:
        Generated report content
    """
    logger.info(f"Generating executive report in {format} format")
    
    data = {
        'key_findings': key_findings
    }
    
    if executive_summary:
        data['executive_summary'] = executive_summary
    
    if conclusions:
        data['conclusions'] = conclusions
    
    generator = ForensicReportGenerator(case_info)
    return generator.generate_report(data, 'executive', format, output_path)