#!/usr/bin/env python3
"""Database initialization script for MCP Security Scanner."""

import sys
from pathlib import Path

# Add parent directory to path for imports
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

from database import init_database

def main():
    """Initialize the database."""
    print("Initializing MCP Security Scanner database...")
    
    try:
        init_database()
        print("✅ Database tables created successfully!")
        print("📍 Database file: ./mcp_security.db")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()