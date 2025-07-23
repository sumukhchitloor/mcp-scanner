#!/bin/bash

# Start the FastAPI backend for MCP Security Scanner

echo "🚀 Starting MCP Security Scanner FastAPI Backend..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate.fish

# Install FastAPI dependencies
echo "📦 Installing FastAPI dependencies..."
pip install -r fastapi_backend/requirements.txt

# Create uploads directory
mkdir -p fastapi_backend/uploads

# Start the server
echo "🌐 Starting server on http://localhost:8000"
cd fastapi_backend
python start.py