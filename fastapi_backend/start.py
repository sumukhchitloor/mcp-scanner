#!/usr/bin/env python3
"""
Startup script for the FastAPI MCP Security Scanner backend.
"""

import uvicorn
import os
import sys
from pathlib import Path

# Add the parent directory to the Python path so we can import mcp_scanner
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

if __name__ == "__main__":
    # Set environment variables
    os.environ.setdefault("PYTHONPATH", str(parent_dir))
    
    # Run the FastAPI server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        reload_dirs=[str(Path(__file__).parent), str(parent_dir / "mcp_scanner")]
    )