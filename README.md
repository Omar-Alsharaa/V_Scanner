# Advanced Virus Scanner & Cleaner

A comprehensive virus scanning and cleaning tool designed to protect your system while ensuring critical files remain safe.

## Features

- Quick, full system, and custom folder scanning
- Real-time threat detection with multiple detection methods
- Safe cleaning that protects system-critical files
- User-friendly graphical interface
- Detailed scan results and statistics
- Comprehensive logging and audit trails
- Automatic backup system before file deletion

## Safety First

This scanner is designed with safety as the top priority. It will never delete system-critical files that are essential for Windows operation, including:

- Core Windows system files
- Boot files and system executables
- Windows Defender components
- Essential system libraries

## Quick Start

1. **Install Python 3.6+** if not already installed
2. **Clone the repository:**
   ```bash
   git clone https://github.com/Omar-Alsharaa/V_Scanner.git
   cd V_Scanner
   ```
3. **Run setup:**
   ```bash
   setup.bat
   ```
4. **Start the scanner:**
   ```bash
   run_scanner.bat
   ```
   Or directly:
   ```bash
   python virus_scanner.py
   ```

## How to Use

1. Choose your scan type:
   - **Quick Scan**: Scans common malware locations
   - **Full System Scan**: Comprehensive system-wide scan
   - **Custom Folder**: Scan a specific directory
2. Click "Start Scan" to begin
3. Review detected threats in the results table
4. Select threats to clean or clean all detected items
5. System-critical files will be protected automatically

## Detection Methods

The scanner uses multiple detection techniques:

- **Hash-based detection** for known malware
- **Pattern matching** for suspicious filenames
- **Content analysis** for malicious code signatures
- **Heuristic analysis** for unknown threats

## System Requirements

- Python 3.6 or higher
- Windows operating system
- Administrator privileges recommended for full system scans

## Installation

### Option 1: Quick Setup
1. Download and extract the repository
2. Run `setup.bat` to verify requirements
3. Run `run_scanner.bat` to start

### Option 2: Manual Setup
```bash
git clone https://github.com/Omar-Alsharaa/V_Scanner.git
cd V_Scanner
python -m pip install --upgrade pip
python virus_scanner.py
```

## Project Structure

```
V_Scanner/
├── virus_scanner.py      # Main application
├── system_protection.py  # System file protection
├── scan_logger.py       # Logging system
├── signatures.json      # Virus signature database
├── config.json         # Configuration settings
├── run_scanner.bat     # Easy launcher
├── setup.bat          # Setup script
├── test_scanner.py    # Test framework
├── README.md          # This file
└── USER_GUIDE.md      # Detailed usage guide
```

## System Protection

The application maintains a comprehensive list of protected files and directories to prevent accidental deletion of critical system components. This ensures your system remains stable and functional after cleaning operations.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Testing

Run the test suite to verify all components:
```bash
python test_scanner.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

This tool is designed for educational and legitimate security purposes only. Always ensure you have proper authorization before scanning systems that don't belong to you.

## Support

- Read the [User Guide](USER_GUIDE.md) for detailed instructions
- Check existing issues before reporting new ones
- Provide detailed information when reporting bugs

## Disclaimer

This software is provided "as is" without warranty. While extensive care has been taken to protect system files, users should always backup important data before running any security tool.
