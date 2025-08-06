#!/usr/bin/env python3
"""
Logging Module for Advanced Virus Scanner
Provides comprehensive logging and audit trail functionality
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path

class ScanLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.setup_logging()
        
    def setup_logging(self):
        """Initialize logging directories and files"""
        try:
            os.makedirs(self.log_dir, exist_ok=True)
            
            # Create log files if they don't exist
            self.scan_log = os.path.join(self.log_dir, "scan_history.json")
            self.threat_log = os.path.join(self.log_dir, "threats_detected.json")
            self.action_log = os.path.join(self.log_dir, "actions_taken.json")
            self.error_log = os.path.join(self.log_dir, "errors.log")
            
            # Initialize log files with empty arrays if they don't exist
            for log_file in [self.scan_log, self.threat_log, self.action_log]:
                if not os.path.exists(log_file):
                    with open(log_file, 'w') as f:
                        json.dump([], f)
                        
        except Exception as e:
            print(f"Warning: Could not setup logging: {e}")
            
    def log_scan_start(self, scan_type, scan_path=None):
        """Log the start of a scan session"""
        try:
            scan_entry = {
                "timestamp": datetime.now().isoformat(),
                "event": "scan_started",
                "scan_type": scan_type,
                "scan_path": scan_path,
                "session_id": int(time.time())
            }
            
            self._append_to_json_log(self.scan_log, scan_entry)
            return scan_entry["session_id"]
            
        except Exception as e:
            self._log_error(f"Error logging scan start: {e}")
            return None
            
    def log_scan_complete(self, session_id, results_summary):
        """Log the completion of a scan session"""
        try:
            scan_entry = {
                "timestamp": datetime.now().isoformat(),
                "event": "scan_completed",
                "session_id": session_id,
                "files_scanned": results_summary.get("files_scanned", 0),
                "threats_found": results_summary.get("threats_found", 0),
                "scan_duration": results_summary.get("duration", 0),
                "errors": results_summary.get("errors", 0)
            }
            
            self._append_to_json_log(self.scan_log, scan_entry)
            
        except Exception as e:
            self._log_error(f"Error logging scan completion: {e}")
            
    def log_threat_detected(self, session_id, filepath, threat_info):
        """Log a detected threat"""
        try:
            threat_entry = {
                "timestamp": datetime.now().isoformat(),
                "session_id": session_id,
                "filepath": filepath,
                "filename": os.path.basename(filepath),
                "threat_type": threat_info.get("threat", "Unknown"),
                "risk_level": threat_info.get("risk", "Unknown"),
                "detection_method": threat_info.get("method", "Unknown"),
                "file_size": self._get_file_size(filepath),
                "file_hash": self._get_file_hash(filepath)
            }
            
            self._append_to_json_log(self.threat_log, threat_entry)
            
        except Exception as e:
            self._log_error(f"Error logging threat detection: {e}")
            
    def log_action_taken(self, session_id, action, filepath, result):
        """Log actions taken on files"""
        try:
            action_entry = {
                "timestamp": datetime.now().isoformat(),
                "session_id": session_id,
                "action": action,  # "deleted", "quarantined", "ignored", etc.
                "filepath": filepath,
                "filename": os.path.basename(filepath),
                "result": result,  # "success", "failed", "skipped"
                "reason": result.get("reason", "") if isinstance(result, dict) else str(result)
            }
            
            self._append_to_json_log(self.action_log, action_entry)
            
        except Exception as e:
            self._log_error(f"Error logging action: {e}")
            
    def get_scan_statistics(self, days=30):
        """Get scan statistics for the specified number of days"""
        try:
            cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
            
            # Load scan history
            with open(self.scan_log, 'r') as f:
                scan_history = json.load(f)
                
            # Load threat history
            with open(self.threat_log, 'r') as f:
                threat_history = json.load(f)
                
            # Filter by time
            recent_scans = [s for s in scan_history 
                          if datetime.fromisoformat(s['timestamp']).timestamp() > cutoff_time]
            recent_threats = [t for t in threat_history 
                            if datetime.fromisoformat(t['timestamp']).timestamp() > cutoff_time]
            
            # Calculate statistics
            stats = {
                "period_days": days,
                "total_scans": len([s for s in recent_scans if s['event'] == 'scan_started']),
                "total_threats": len(recent_threats),
                "files_scanned": sum(s.get('files_scanned', 0) 
                                   for s in recent_scans if s['event'] == 'scan_completed'),
                "threat_types": {},
                "risk_levels": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                "most_recent_scan": max([s['timestamp'] for s in recent_scans]) if recent_scans else None
            }
            
            # Analyze threat types and risk levels
            for threat in recent_threats:
                threat_type = threat.get('threat_type', 'Unknown')
                risk_level = threat.get('risk_level', 'Unknown')
                
                stats["threat_types"][threat_type] = stats["threat_types"].get(threat_type, 0) + 1
                if risk_level in stats["risk_levels"]:
                    stats["risk_levels"][risk_level] += 1
                    
            return stats
            
        except Exception as e:
            self._log_error(f"Error generating statistics: {e}")
            return None
            
    def export_logs(self, output_file):
        """Export all logs to a single file"""
        try:
            export_data = {
                "export_timestamp": datetime.now().isoformat(),
                "scan_history": [],
                "threat_history": [],
                "action_history": []
            }
            
            # Load all log files
            log_files = [
                (self.scan_log, "scan_history"),
                (self.threat_log, "threat_history"),
                (self.action_log, "action_history")
            ]
            
            for log_file, key in log_files:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        export_data[key] = json.load(f)
                        
            # Write export file
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
                
            return True
            
        except Exception as e:
            self._log_error(f"Error exporting logs: {e}")
            return False
            
    def _append_to_json_log(self, log_file, entry):
        """Append entry to JSON log file"""
        try:
            # Read existing entries
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    entries = json.load(f)
            else:
                entries = []
                
            # Append new entry
            entries.append(entry)
            
            # Keep only last 10000 entries to prevent file from growing too large
            if len(entries) > 10000:
                entries = entries[-10000:]
                
            # Write back
            with open(log_file, 'w') as f:
                json.dump(entries, f, indent=2)
                
        except Exception as e:
            self._log_error(f"Error writing to log file {log_file}: {e}")
            
    def _log_error(self, error_message):
        """Log error to error log file"""
        try:
            timestamp = datetime.now().isoformat()
            with open(self.error_log, 'a', encoding='utf-8') as f:
                f.write(f"{timestamp}: {error_message}\n")
        except Exception:
            print(f"Critical: Could not write error log: {error_message}")
            
    def _get_file_size(self, filepath):
        """Get file size safely"""
        try:
            return os.path.getsize(filepath)
        except Exception:
            return -1
            
    def _get_file_hash(self, filepath):
        """Get file hash safely"""
        try:
            import hashlib
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return None

# Example usage
if __name__ == "__main__":
    logger = ScanLogger()
    
    # Test logging
    session_id = logger.log_scan_start("quick", "C:\\Temp")
    
    # Simulate threat detection
    logger.log_threat_detected(session_id, "C:\\Temp\\suspicious.exe", {
        "threat": "Generic.Malware",
        "risk": "High",
        "method": "signature_match"
    })
    
    # Log action taken
    logger.log_action_taken(session_id, "deleted", "C:\\Temp\\suspicious.exe", "success")
    
    # Complete scan
    logger.log_scan_complete(session_id, {
        "files_scanned": 1250,
        "threats_found": 1,
        "duration": 45.5,
        "errors": 0
    })
    
    # Get statistics
    stats = logger.get_scan_statistics(7)
    if stats:
        print("Scan Statistics (Last 7 days):")
        print(f"Total Scans: {stats['total_scans']}")
        print(f"Total Threats: {stats['total_threats']}")
        print(f"Files Scanned: {stats['files_scanned']}")
        print(f"Threat Types: {stats['threat_types']}")
        print(f"Risk Levels: {stats['risk_levels']}")
