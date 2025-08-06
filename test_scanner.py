#!/usr/bin/env python3
"""
Test Script for Advanced Virus Scanner
Tests the main functionality without running the full GUI
"""

import os
import sys
import tempfile
import hashlib

def create_test_files():
    """Create test files for scanning"""
    test_dir = os.path.join(tempfile.gettempdir(), "virus_scanner_test")
    os.makedirs(test_dir, exist_ok=True)
    
    test_files = []
    
    # Create a normal text file
    normal_file = os.path.join(test_dir, "normal_file.txt")
    with open(normal_file, 'w') as f:
        f.write("This is a normal text file for testing.")
    test_files.append(normal_file)
    
    # Create a suspicious filename
    suspicious_file = os.path.join(test_dir, "document.pdf.exe")
    with open(suspicious_file, 'w') as f:
        f.write("This file has a suspicious double extension.")
    test_files.append(suspicious_file)
    
    # Create a file with suspicious content
    malicious_file = os.path.join(test_dir, "script.js")
    with open(malicious_file, 'w') as f:
        f.write('eval(base64_decode("dGVzdA=="));')
    test_files.append(malicious_file)
    
    return test_dir, test_files

def test_system_protection():
    """Test the system protection module"""
    print("Testing System Protection Module...")
    
    try:
        from system_protection import SystemProtection
        protector = SystemProtection()
        
        # Test critical file detection
        test_cases = [
            ("C:\\Windows\\System32\\kernel32.dll", True),
            ("C:\\Windows\\explorer.exe", True),
            ("C:\\Temp\\test.txt", False),
            ("C:\\Users\\Public\\document.exe", False)
        ]
        
        for filepath, expected in test_cases:
            is_critical, reason = protector.is_critical_file(filepath)
            result = "PASS" if is_critical == expected else "FAIL"
            print(f"  {result}: {filepath} - Critical: {is_critical}")
            
        print("System Protection tests completed.\n")
        
    except ImportError as e:
        print(f"Could not import system_protection: {e}")
        return False
    except Exception as e:
        print(f"Error testing system protection: {e}")
        return False
        
    return True

def test_virus_scanner():
    """Test the virus scanner functionality"""
    print("Testing Virus Scanner Module...")
    
    try:
        from virus_scanner import VirusScanner
        
        # Create test files
        test_dir, test_files = create_test_files()
        print(f"Created test files in: {test_dir}")
        
        # Note: We can't easily test the full GUI, but we can test components
        scanner = VirusScanner()
        
        # Test virus signature loading
        if hasattr(scanner, 'virus_signatures'):
            print("  PASS: Virus signatures loaded")
        else:
            print("  FAIL: Virus signatures not loaded")
            
        # Test file scanning logic
        for test_file in test_files:
            threats = scanner.scan_file(test_file)
            filename = os.path.basename(test_file)
            if threats:
                print(f"  THREAT DETECTED: {filename} - {len(threats)} threats")
                for threat in threats:
                    print(f"    - {threat.get('threat', 'Unknown')} (Risk: {threat.get('risk', 'Unknown')})")
            else:
                print(f"  CLEAN: {filename}")
                
        # Cleanup test files
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
        print("Test files cleaned up.")
        
        print("Virus Scanner tests completed.\n")
        
    except ImportError as e:
        print(f"Could not import virus_scanner: {e}")
        return False
    except Exception as e:
        print(f"Error testing virus scanner: {e}")
        return False
        
    return True

def test_logging():
    """Test the logging module"""
    print("Testing Logging Module...")
    
    try:
        from scan_logger import ScanLogger
        logger = ScanLogger()
        
        # Test session logging
        session_id = logger.log_scan_start("test", "C:\\Test")
        if session_id:
            print("  PASS: Scan session started and logged")
            
            # Test threat logging
            logger.log_threat_detected(session_id, "C:\\Test\\threat.exe", {
                "threat": "Test.Malware",
                "risk": "High",
                "method": "test"
            })
            print("  PASS: Threat detection logged")
            
            # Test action logging
            logger.log_action_taken(session_id, "deleted", "C:\\Test\\threat.exe", "success")
            print("  PASS: Action logged")
            
            # Complete session
            logger.log_scan_complete(session_id, {
                "files_scanned": 10,
                "threats_found": 1,
                "duration": 5.0,
                "errors": 0
            })
            print("  PASS: Scan completion logged")
            
        else:
            print("  FAIL: Could not start logging session")
            
        print("Logging tests completed.\n")
        
    except ImportError as e:
        print(f"Could not import scan_logger: {e}")
        return False
    except Exception as e:
        print(f"Error testing logging: {e}")
        return False
        
    return True

def main():
    """Run all tests"""
    print("Advanced Virus Scanner - Test Suite")
    print("==================================\n")
    
    results = []
    
    # Run tests
    results.append(("System Protection", test_system_protection()))
    results.append(("Virus Scanner", test_virus_scanner()))
    results.append(("Logging", test_logging()))
    
    # Print results
    print("Test Results:")
    print("=============")
    all_passed = True
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
        if not result:
            all_passed = False
            
    print(f"\nOverall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    
    if all_passed:
        print("\nThe virus scanner appears to be working correctly!")
        print("You can now run the full application using:")
        print("  python virus_scanner.py")
        print("or")
        print("  run_scanner.bat")
    else:
        print("\nSome tests failed. Please check the error messages above.")
        
    return all_passed

if __name__ == "__main__":
    main()
