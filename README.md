# Advanced Virus Scanner & Cleaner

A comprehensive virus scanning and cleaning tool designed to protect your system while ensuring critical files remain safe.

## Features

- Quick, full system, and custom folder scanning
- Real-time threat detection with multiple detection methods
- Safe cleaning that protects system-critical files
- User-friendly graphical interface
- Detailed scan results and statistics

## Safety First

This scanner is designed with safety as the top priority. It will never delete system-critical files that are essential for Windows operation, including:

- Core Windows system files
- Boot files and system executables
- Windows Defender components
- Essential system libraries

## How to Use

1. Run the application by double-clicking `run_scanner.bat` or running `python virus_scanner.py`
2. Choose your scan type:
   - Quick Scan: Scans common malware locations
   - Full System Scan: Comprehensive system-wide scan
   - Custom Folder: Scan a specific directory
3. Click "Start Scan" to begin
4. Review detected threats in the results table
5. Select threats to clean or clean all detected items
6. System-critical files will be protected automatically

## Detection Methods

The scanner uses multiple detection techniques:

- Hash-based detection for known malware
- Pattern matching for suspicious filenames
- Content analysis for malicious code signatures
- Heuristic analysis for unknown threats

## Requirements

- Python 3.6 or higher
- Windows operating system
- Administrator privileges recommended for full system scans

## Installation

1. Ensure Python is installed on your system
2. Run `run_scanner.bat` to start the application
3. No additional installation required

## System Protection

The application maintains a comprehensive list of protected files and directories to prevent accidental deletion of critical system components. This ensures your system remains stable and functional after cleaning operations.

## Support

This tool is designed to be intuitive and safe. If you encounter any issues, ensure you have appropriate permissions and that Python is correctly installed on your system.
