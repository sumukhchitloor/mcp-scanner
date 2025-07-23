#!/usr/bin/env python3
"""Add sample data to the database for testing."""

import sys
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path for imports
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

try:
    from database import get_db_session, Scan, Vulnerability
    from database_service import db_service
except ImportError:
    # Fallback for direct execution
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from database import get_db_session, Scan, Vulnerability
    from database_service import db_service

def create_sample_scans():
    """Create sample scan records for testing."""
    
    sample_scans = [
        {
            "target_path": "/app/mcp-server",
            "files_scanned": 25,
            "ai_provider": "openai",
            "vulnerabilities": [
                {"type": "command_injection", "severity": "CRITICAL", "file_path": "server.py", "line_number": 45},
                {"type": "sql_injection", "severity": "HIGH", "file_path": "database.py", "line_number": 123},
                {"type": "authentication", "severity": "MEDIUM", "file_path": "auth.py", "line_number": 67}
            ]
        },
        {
            "target_path": "/api/authentication",
            "files_scanned": 12,
            "ai_provider": "gemini", 
            "vulnerabilities": [
                {"type": "authentication", "severity": "HIGH", "file_path": "login.py", "line_number": 34}
            ]
        },
        {
            "target_path": "/lib/security-utils",
            "files_scanned": 8,
            "ai_provider": None,  # Static only
            "vulnerabilities": []
        }
    ]
    
    created_scans = []
    
    for i, scan_data in enumerate(sample_scans):
        scan_id = str(uuid.uuid4())
        start_time = datetime.now() - timedelta(hours=i * 2)
        end_time = start_time + timedelta(minutes=30)
        
        # Create scan in database
        scan_record = {
            "id": scan_id,
            "target_path": scan_data["target_path"],
            "startTime": start_time.isoformat(),
            "status": "running",
            "files": scan_data["files_scanned"],
            "config": {
                "ai_provider": scan_data["ai_provider"],
                "static_only": scan_data["ai_provider"] is None
            }
        }
        
        db_service.create_scan(scan_record)
        
        # Create vulnerabilities
        vulnerabilities_data = []
        for j, vuln in enumerate(scan_data["vulnerabilities"]):
            vuln_data = {
                "id": f"{scan_id}_vuln_{j}",
                "type": vuln["type"],
                "severity": vuln["severity"],
                "file_path": vuln["file_path"],
                "line_number": vuln["line_number"],
                "code_snippet": f"# Sample code snippet from {vuln['file_path']}",
                "description": f"{vuln['type'].replace('_', ' ').title()} vulnerability detected",
                "recommendation": f"Fix the {vuln['type'].replace('_', ' ')} vulnerability",
                "confidence": 85.0,
                "detector": "ai_analyzer" if scan_data["ai_provider"] else "static_analyzer"
            }
            vulnerabilities_data.append(vuln_data)
        
        # Complete the scan
        scan_results = {
            "vulnerabilities": vulnerabilities_data,
            "total_vulnerabilities": len(vulnerabilities_data),
            "scan_duration": 30.0,
            "files_scanned": scan_data["files_scanned"]
        }
        
        db_service.complete_scan(scan_id, scan_results)
        created_scans.append(scan_id)
        
        print(f"✅ Created sample scan: {scan_data['target_path']} ({len(vulnerabilities_data)} vulnerabilities)")
    
    return created_scans

def main():
    """Add sample data to the database."""
    print("Adding sample data to MCP Security Scanner database...")
    
    try:
        created_scans = create_sample_scans()
        print(f"\n🎉 Successfully created {len(created_scans)} sample scans!")
        print("📊 Dashboard and scan history should now show real data.")
        
    except Exception as e:
        print(f"❌ Error adding sample data: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()