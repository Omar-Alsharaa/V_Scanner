# Advanced Virus Scanner - User Guide

## Quick Start

1. Run `setup.bat` to verify your system is ready
2. Double-click `run_scanner.bat` to start the application
3. Choose your scan type and click "Start Scan"
4. Review results and clean threats as needed

## Scan Types

### Quick Scan
- Scans common malware locations
- Downloads folder, Desktop, Documents, Public folders
- Fastest option, usually completes in 1-5 minutes
- Recommended for daily use

### Full System Scan
- Comprehensive scan of entire C: drive
- Takes longer but provides maximum protection
- Recommended weekly or monthly
- May take 30 minutes to several hours depending on system size

### Custom Folder Scan
- Scan specific folders or drives
- Useful for checking USB drives or downloaded files
- Click "Browse" to select the folder

## Understanding Results

### Threat Categories
- **High Risk**: Confirmed malware or highly suspicious files
- **Medium Risk**: Potentially unwanted programs or suspicious patterns
- **Low Risk**: Files that may be false positives but worth reviewing

### Status Column
- **Safe to remove**: File can be safely deleted
- **CRITICAL SYSTEM FILE**: Protected system file that will not be deleted

## Safety Features

### System Protection
The scanner automatically protects critical system files including:
- Windows system files (kernel32.dll, explorer.exe, etc.)
- Boot files and system executables
- Windows Defender components
- Essential system libraries

### Backup System
- All deleted files are backed up before removal
- Backups stored in the "backup" folder
- Files can be restored if needed

## Detection Methods

### Hash-based Detection
- Compares file fingerprints against known malware database
- Most accurate method for known threats
- Updated regularly with new signatures

### Pattern Matching
- Detects suspicious file naming patterns
- Double extensions (.exe.exe, .pdf.exe)
- Common malware file types

### Content Analysis
- Scans file contents for malicious code patterns
- Detects obfuscated scripts and suspicious commands
- Works on text-based files

## Best Practices

### Regular Scanning
- Run Quick Scan daily
- Run Full System Scan weekly
- Scan all external media before use

### Safe Computing
- Keep the signature database updated
- Don't disable real-time protection
- Be cautious with email attachments and downloads

### System Maintenance
- Review scan logs regularly
- Keep the backup folder clean
- Update Windows and other software regularly

## Troubleshooting

### Scanner Won't Start
- Ensure Python is installed and in PATH
- Run `setup.bat` to check requirements
- Check for antivirus blocking the application

### False Positives
- Review detected files carefully
- System files are automatically protected
- Use custom scan to recheck specific files

### Performance Issues
- Close other applications during full scans
- Exclude large media folders if scan is too slow
- Use Quick Scan for routine checks

## Log Files

The scanner maintains detailed logs in the "logs" folder:
- `scan_history.json`: Record of all scans performed
- `threats_detected.json`: Details of all detected threats
- `actions_taken.json`: Record of cleaning actions
- `errors.log`: Any errors encountered during operation

## Configuration

Edit `config.json` to customize scanner behavior:
- Maximum file size to scan
- Enable/disable specific detection methods
- Interface preferences
- Logging levels

## Advanced Usage

### Command Line Testing
Run `python test_scanner.py` to verify all components are working correctly.

### Manual Signature Updates
Update `signatures.json` with new malware signatures as they become available.

### Custom Whitelist
Add trusted files or folders to the configuration to prevent false positives.

## Support and Maintenance

### Regular Updates
- Check for signature database updates
- Update the scanner software periodically
- Keep Windows and Python updated

### Data Privacy
- All scans are performed locally
- No data is sent to external servers
- Logs are stored only on your system

### Performance Monitoring
- Review scan statistics regularly
- Monitor system performance during scans
- Adjust scan schedules based on usage patterns
