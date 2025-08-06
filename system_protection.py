#!/usr/bin/env python3
"""
System Protection Module
Provides comprehensive protection for system-critical files and processes
"""

import os
import sys
import winreg
from pathlib import Path

class SystemProtection:
    def __init__(self):
        self.load_critical_components()
        
    def load_critical_components(self):
        """Load comprehensive list of critical system components"""
        
        # Critical system files that should never be deleted
        self.critical_files = {
            # Core Windows files
            'ntoskrnl.exe', 'ntdll.dll', 'kernel32.dll', 'user32.dll',
            'gdi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll',
            'advapi32.dll', 'rpcrt4.dll', 'comctl32.dll', 'comdlg32.dll',
            'wininet.dll', 'urlmon.dll', 'shlwapi.dll', 'version.dll',
            'msvcrt.dll', 'ws2_32.dll', 'wsock32.dll', 'netapi32.dll',
            
            # System processes
            'explorer.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'taskeng.exe',
            'dwm.exe', 'windefend.exe', 'wininit.exe', 'taskhost.exe',
            
            # Boot and recovery files
            'bootmgr', 'bootmgfw.efi', 'winload.exe', 'winresume.exe',
            'bcd', 'bootstat.dat', 'pagefile.sys', 'hiberfil.sys',
            
            # Security components
            'mpsigdnldr.exe', 'mpsigdntr.exe', 'mpengine.dll',
            'antimalware service executable', 'msmpeng.exe',
            
            # Driver files
            'hal.dll', 'ntoskrnl.exe', 'ntkrnlpa.exe', 'ntkrpamp.exe',
        }
        
        # Critical directories
        self.critical_directories = {
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Windows\\Boot',
            'C:\\Windows\\Fonts',
            'C:\\Windows\\WinSxS',
            'C:\\Windows\\servicing',
            'C:\\Program Files\\Windows Defender',
            'C:\\Program Files\\Windows Security',
            'C:\\Program Files\\Common Files\\Microsoft Shared',
            'C:\\ProgramData\\Microsoft\\Windows Defender',
            'C:\\ProgramData\\Microsoft\\Windows Security Health',
        }
        
        # Critical registry keys
        self.critical_registry_keys = {
            'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services',
            'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
            'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot',
        }
        
        # File extensions that are typically system files
        self.system_extensions = {
            '.dll', '.sys', '.drv', '.exe', '.ocx', '.cpl', '.scr', '.msc'
        }
        
    def is_critical_file(self, filepath):
        """
        Determine if a file is critical to system operation
        Returns: (is_critical, reason)
        """
        try:
            filepath = os.path.abspath(filepath).lower()
            filename = os.path.basename(filepath)
            
            # Check if it's in the critical files list
            if filename in self.critical_files:
                return True, f"Critical system file: {filename}"
                
            # Check if it's in a critical directory
            for critical_dir in self.critical_directories:
                if filepath.startswith(critical_dir.lower()):
                    return True, f"Located in critical directory: {critical_dir}"
                    
            # Check if it's a Windows system file by location
            if ('\\windows\\system32\\' in filepath or 
                '\\windows\\syswow64\\' in filepath or
                '\\program files\\windows' in filepath):
                return True, "Windows system file location"
                
            # Check if it's a driver file
            if filepath.endswith('.sys') and ('\\drivers\\' in filepath or '\\system32\\' in filepath):
                return True, "System driver file"
                
            # Check if it's in Program Files and has system-like characteristics
            if ('\\program files\\' in filepath and 
                any(filepath.endswith(ext) for ext in self.system_extensions)):
                # Additional check for known safe publishers would go here
                pass
                
            return False, ""
            
        except Exception as e:
            # If we can't determine, err on the side of caution
            return True, f"Error analyzing file: {e}"
            
    def is_safe_to_delete(self, filepath):
        """
        Comprehensive check if a file is safe to delete
        Returns: (is_safe, risk_level, reason)
        """
        is_critical, reason = self.is_critical_file(filepath)
        
        if is_critical:
            return False, "CRITICAL", reason
            
        # Additional safety checks
        try:
            # Check if file is currently in use
            if self.is_file_in_use(filepath):
                return False, "HIGH", "File is currently in use by system"
                
            # Check if it's a recently modified system file
            if self.is_recently_modified_system_file(filepath):
                return False, "MEDIUM", "Recently modified system file"
                
            # Check file signature/publisher
            if self.has_microsoft_signature(filepath):
                return False, "HIGH", "Microsoft signed file"
                
            return True, "LOW", "Safe to delete"
            
        except Exception as e:
            return False, "HIGH", f"Error during safety check: {e}"
            
    def is_file_in_use(self, filepath):
        """Check if a file is currently in use"""
        try:
            # Try to open the file exclusively
            with open(filepath, 'r+b'):
                return False
        except IOError:
            return True
        except Exception:
            return True  # Assume in use if we can't check
            
    def is_recently_modified_system_file(self, filepath):
        """Check if file was recently modified and might be a system file"""
        try:
            import time
            stat = os.stat(filepath)
            
            # If modified in the last 7 days and in a system location
            if (time.time() - stat.st_mtime) < (7 * 24 * 3600):
                filepath_lower = filepath.lower()
                if ('\\windows\\' in filepath_lower or 
                    '\\program files\\' in filepath_lower):
                    return True
            return False
        except Exception:
            return False
            
    def has_microsoft_signature(self, filepath):
        """Check if file has a Microsoft digital signature"""
        try:
            # This is a simplified check - in a real implementation,
            # you would use Windows API calls to verify digital signatures
            import subprocess
            
            # Use PowerShell to check file signature
            cmd = f'Get-AuthenticodeSignature "{filepath}" | Select-Object -ExpandProperty SignerCertificate | Select-Object -ExpandProperty Subject'
            result = subprocess.run(['powershell', '-Command', cmd], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and 'Microsoft' in result.stdout:
                return True
                
        except Exception:
            pass
            
        return False
        
    def create_backup(self, filepath, backup_dir):
        """Create a backup of a file before deletion"""
        try:
            import shutil
            os.makedirs(backup_dir, exist_ok=True)
            
            filename = os.path.basename(filepath)
            backup_path = os.path.join(backup_dir, filename)
            
            # If backup already exists, add timestamp
            if os.path.exists(backup_path):
                import time
                timestamp = int(time.time())
                name, ext = os.path.splitext(filename)
                backup_path = os.path.join(backup_dir, f"{name}_{timestamp}{ext}")
                
            shutil.copy2(filepath, backup_path)
            return backup_path
            
        except Exception as e:
            raise Exception(f"Failed to create backup: {e}")
            
    def safe_delete(self, filepath, backup_dir="backup"):
        """Safely delete a file with backup and verification"""
        try:
            # Perform safety check
            is_safe, risk_level, reason = self.is_safe_to_delete(filepath)
            
            if not is_safe:
                raise Exception(f"Cannot delete file: {reason} (Risk: {risk_level})")
                
            # Create backup
            backup_path = self.create_backup(filepath, backup_dir)
            
            # Delete the file
            os.remove(filepath)
            
            return True, f"File deleted successfully. Backup created at: {backup_path}"
            
        except Exception as e:
            return False, str(e)
            
    def get_system_info(self):
        """Get basic system information for logging"""
        try:
            import platform
            return {
                'os': platform.system(),
                'version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'python_version': platform.python_version()
            }
        except Exception:
            return {'error': 'Could not retrieve system information'}

# Example usage and testing
if __name__ == "__main__":
    protector = SystemProtection()
    
    # Test some files
    test_files = [
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\explorer.exe",
        "C:\\Users\\Public\\test.txt",
        "C:\\Temp\\suspicious.exe"
    ]
    
    for filepath in test_files:
        if os.path.exists(filepath):
            is_critical, reason = protector.is_critical_file(filepath)
            is_safe, risk_level, safe_reason = protector.is_safe_to_delete(filepath)
            print(f"\nFile: {filepath}")
            print(f"Critical: {is_critical} - {reason}")
            print(f"Safe to delete: {is_safe} (Risk: {risk_level}) - {safe_reason}")
