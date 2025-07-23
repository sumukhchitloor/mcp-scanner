# MCP Security Scanner - FastAPI Backend

This is the FastAPI backend that replaces the original Express.js backend, providing RESTful API endpoints for the MCP Security Scanner frontend.

## Features

- **FastAPI Framework**: Modern, fast web framework with automatic API documentation
- **File Upload Support**: Multi-file upload with validation
- **Background Scanning**: Asynchronous security scanning with progress tracking
- **CORS Support**: Configured for frontend development servers
- **Comprehensive Logging**: Structured logging for debugging and monitoring
- **Type Safety**: Full Pydantic model validation

## API Endpoints

### Core Endpoints
- `GET /api/health` - Health check
- `GET /api/scanner/status` - Scanner capabilities and status
- `POST /api/scanner/upload` - Upload files for scanning
- `POST /api/scanner/scan` - Start a security scan
- `GET /api/scanner/scan/{scan_id}` - Get scan status and progress
- `GET /api/scanner/results/{scan_id}` - Get detailed scan results
- `GET /api/scanner/recent` - Get recent scan history

### Documentation
- `GET /api/docs` - Interactive Swagger UI documentation
- `GET /api/redoc` - ReDoc API documentation

## Installation

1. **Install Dependencies**:
   ```bash
   pip install -r fastapi_backend/requirements.txt
   ```

2. **Start the Server**:
   ```bash
   ./start_fastapi.sh
   ```

   Or manually:
   ```bash
   cd fastapi_backend
   python start.py
   ```

3. **Test the Connection**:
   ```bash
   python test_connection.py
   ```

## Configuration

### Environment Variables
- `PYTHONPATH`: Automatically set to include the mcp_scanner module
- Server runs on `http://localhost:8000` by default

### CORS Configuration
Configured to allow requests from:
- `http://localhost:3000` (React dev server)
- `http://localhost:5173` (Vite dev server)

## File Upload

- **Supported Formats**: `.js`, `.jsx`, `.ts`, `.tsx`, `.py`, `.json`, `.yml`, `.yaml`
- **Max File Size**: 50MB per file
- **Max Files**: 10 files per upload
- **Storage**: Files are temporarily stored in `fastapi_backend/uploads/`
- **Cleanup**: Files are automatically cleaned up after scanning

## Scanning Process

1. **Upload Files**: Files are uploaded and stored temporarily
2. **Start Scan**: Background task starts the MCP scanner CLI
3. **Monitor Progress**: Real-time progress updates via status endpoint
4. **Get Results**: Detailed vulnerability results when scan completes
5. **Cleanup**: Temporary files are removed after processing

## Integration with MCP Scanner

The FastAPI backend integrates with the existing MCP scanner CLI by:

1. **Subprocess Execution**: Calls the `mcp_scanner/cli.py` script
2. **JSON Output**: Parses JSON results from the scanner
3. **Progress Tracking**: Monitors scanner output for progress updates
4. **Error Handling**: Captures and reports scanner errors

## Development

### Hot Reload
The server supports hot reload for development:
- Changes to FastAPI code trigger automatic reloads
- Changes to `mcp_scanner` module also trigger reloads

### Logging
Comprehensive logging is configured:
- INFO level for normal operations
- ERROR level for failures
- All logs include timestamps and context

### Testing
Use the provided test script:
```bash
python test_connection.py
```

This will test:
- Health check endpoint
- Scanner status
- File upload functionality
- Scan start and monitoring
- Result retrieval

## Deployment

For production deployment:

1. **Use Production WSGI Server**:
   ```bash
   pip install gunicorn
   gunicorn fastapi_backend.main:app -w 4 -k uvicorn.workers.UvicornWorker
   ```

2. **Configure Environment**:
   - Set appropriate CORS origins
   - Configure file storage location
   - Set up proper logging

3. **Security Considerations**:
   - Configure proper authentication if needed
   - Set up rate limiting
   - Configure reverse proxy (nginx)

## Troubleshooting

### Common Issues

1. **Import Errors**: Make sure the virtual environment is activated and all dependencies are installed
2. **Scanner Not Found**: Ensure the `mcp_scanner` module is in the Python path
3. **File Upload Issues**: Check file permissions and disk space in the uploads directory
4. **Scan Failures**: Check the MCP scanner dependencies and configuration

### Debug Mode
Enable verbose logging by setting log level to DEBUG in the code.