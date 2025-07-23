import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import subprocess
import tempfile
import shutil

# Add parent directory to path for imports
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

from fastapi import FastAPI, File, UploadFile, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Import MCP Scanner directly
try:
    from mcp_scanner.scanner import SecurityScanner
    from mcp_scanner.utils.report_generator import ReportGenerator
    from mcp_scanner.models.vulnerability import VulnerabilitySeverity
    SCANNER_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Could not import MCP Scanner: {e}")
    SCANNER_AVAILABLE = False

# Import database components
try:
    # Try relative imports first (when running as module)
    from .database import init_database
    from .database_service import db_service
except ImportError:
    # Fallback to absolute imports (when running directly)
    from database import init_database
    from database_service import db_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app configuration
app = FastAPI(
    title="MCP Security Scanner API",
    description="FastAPI backend for MCP Security Scanner",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", 
        "http://localhost:3001", 
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models
class VulnerabilitySeverity(str):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class VulnerabilityType(str):
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    TOOL_POISONING = "tool_poisoning"
    AUTHENTICATION = "authentication"
    CREDENTIALS = "credentials"
    FILE_SECURITY = "file_security"
    INPUT_VALIDATION = "input_validation"
    PROMPT_INJECTION = "prompt_injection"
    CRYPTOGRAPHY = "cryptography"
    NETWORK_SECURITY = "network_security"
    OTHER = "other"

class Vulnerability(BaseModel):
    id: str
    type: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    confidence: float
    detector: str
    rule_name: Optional[str] = None
    cwe_id: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None

class SeverityCounts(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0

class ScanResult(BaseModel):
    id: str
    target_path: str
    start_time: str
    end_time: Optional[str] = None
    scan_duration: Optional[float] = None
    files_scanned: int = 0
    files_skipped: int = 0
    total_vulnerabilities: int = 0
    vulnerabilities: List[Vulnerability] = []
    severity_counts: SeverityCounts = SeverityCounts()
    errors: List[str] = []
    scanner_version: str = "1.0.0"

class ScanConfig(BaseModel):
    files: List[str]
    enableAI: bool = True
    enableStatic: bool = True
    static_only: bool = False
    ai_only: bool = False
    output_format: str = "json"
    ai_provider: Optional[str] = "openai"
    api_key: Optional[str] = None
    excludePatterns: List[str] = []
    verbose: bool = False

class UploadedFile(BaseModel):
    id: str
    originalName: str
    fileName: str
    path: str
    size: int
    mimeType: str
    uploadedAt: str

class FileUploadResponse(BaseModel):
    success: bool
    files: List[UploadedFile]
    message: str

class ScanStartResponse(BaseModel):
    success: bool
    scanId: str
    status: str
    message: str
    estimatedDuration: int

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str

class ScannerStatusResponse(BaseModel):
    isOnline: bool
    version: str
    supportedFormats: List[str]
    maxFileSize: str
    features: Dict[str, bool]

# In-memory storage for active scans and files
active_scans: Dict[str, Dict] = {}
uploaded_files: Dict[str, str] = {}

# Storage directories
UPLOAD_DIR = Path(__file__).parent / "uploads"
RESULTS_DIR = Path(__file__).parent / "scan_results"
ACTIVE_SCANS_FILE = Path(__file__).parent / "active_scans.json"
UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

def save_scan_result(scan_id: str, scan_data: Dict):
    """Save scan result to persistent storage."""
    try:
        result_file = RESULTS_DIR / f"{scan_id}.json"
        with open(result_file, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)
        logger.info(f"Scan result saved to {result_file}")
    except Exception as e:
        logger.error(f"Failed to save scan result {scan_id}: {e}")

def load_scan_result(scan_id: str) -> Optional[Dict]:
    """Load scan result from persistent storage."""
    try:
        result_file = RESULTS_DIR / f"{scan_id}.json"
        if result_file.exists():
            with open(result_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load scan result {scan_id}: {e}")
    return None

def save_active_scans():
    """Save active scans to persistent storage."""
    try:
        with open(ACTIVE_SCANS_FILE, 'w') as f:
            # Save all scans currently in memory (including completed ones for frontend access)
            json.dump(active_scans, f, indent=2, default=str)
        logger.debug(f"Saved {len(active_scans)} scans to persistent storage")
    except Exception as e:
        logger.error(f"Failed to save active scans: {e}")

def cleanup_completed_scans():
    """Remove completed scans from active_scans after they've been available for a while."""
    from datetime import datetime, timedelta
    import dateutil.parser
    
    current_time = datetime.now()
    cutoff_time = current_time - timedelta(minutes=5)  # Keep completed scans for 5 minutes
    
    completed_keys = []
    for scan_id, scan_data in active_scans.items():
        if scan_data.get("status") in ["completed", "failed", "cancelled"]:
            # Check if scan has been completed for more than 5 minutes
            end_time_str = scan_data.get("endTime")
            if end_time_str:
                try:
                    end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
                    if end_time < cutoff_time:
                        completed_keys.append(scan_id)
                except:
                    # If we can't parse the time, remove it anyway
                    completed_keys.append(scan_id)
    
    for key in completed_keys:
        active_scans.pop(key, None)
    
    if completed_keys:
        logger.debug(f"Cleaned up {len(completed_keys)} old completed scans from memory")
        save_active_scans()  # Update persistent storage

def load_active_scans():
    """Load active scans from persistent storage."""
    try:
        if ACTIVE_SCANS_FILE.exists():
            with open(ACTIVE_SCANS_FILE, 'r') as f:
                loaded_scans = json.load(f)
                active_scans.update(loaded_scans)
                logger.info(f"Loaded {len(loaded_scans)} active scans from persistent storage")
                return loaded_scans
    except Exception as e:
        logger.error(f"Failed to load active scans: {e}")
    return {}

def load_all_scan_results() -> List[Dict]:
    """Load all saved scan results on startup."""
    results = []
    try:
        for result_file in RESULTS_DIR.glob("*.json"):
            try:
                with open(result_file, 'r') as f:
                    scan_data = json.load(f)
                    results.append(scan_data)
                    # Also restore to active_scans if recent
                    scan_id = scan_data.get("id")
                    if scan_id:
                        active_scans[scan_id] = scan_data
            except Exception as e:
                logger.error(f"Failed to load scan result from {result_file}: {e}")
        
        logger.info(f"Loaded {len(results)} saved scan results")
    except Exception as e:
        logger.error(f"Failed to load scan results directory: {e}")
    
    return results

# Initialize database
init_database()
logger.info("Database initialized")

# Load existing scan results on startup
startup_results = load_all_scan_results()

# Load active scans from persistent storage
load_active_scans()

# Cleanup task reference
cleanup_task = None

async def periodic_cleanup():
    """Periodically clean up old completed scans."""
    while True:
        await asyncio.sleep(300)  # Run every 5 minutes
        cleanup_completed_scans()

# API Events
@app.on_event("startup")
async def startup_event():
    """Start background tasks on app startup."""
    global cleanup_task
    import asyncio
    cleanup_task = asyncio.create_task(periodic_cleanup())
    logger.info("Started periodic cleanup task")

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up background tasks on app shutdown."""
    global cleanup_task
    if cleanup_task:
        cleanup_task.cancel()
        logger.info("Stopped periodic cleanup task")

# API Routes

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        version="1.0.0"
    )

@app.get("/api/scanner/status", response_model=ScannerStatusResponse)
async def get_scanner_status():
    """Get scanner status and capabilities."""
    return ScannerStatusResponse(
        isOnline=True,
        version="1.0.0",
        supportedFormats=[".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".yml", ".yaml"],
        maxFileSize="50MB",
        features={
            "staticAnalysis": True,
            "aiAnalysis": True,
            "multipleFiles": True
        }
    )

@app.post("/api/scanner/upload", response_model=FileUploadResponse)
async def upload_files(files: List[UploadFile] = File(...)):
    """Upload files for scanning."""
    if not files or len(files) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files uploaded"
        )
    
    # Limit number of files to prevent overwhelming the system
    if len(files) > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many files. Maximum number of files is 1000, but {len(files)} were provided."
        )
    
    uploaded_file_objects = []
    
    try:
        for file in files:
            # Validate file type
            allowed_extensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.json', '.yml', '.yaml']
            file_ext = Path(file.filename).suffix.lower()
            
            if file_ext not in allowed_extensions:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File type {file_ext} not allowed"
                )
            
            # Generate unique filename - flatten the path to avoid directory issues
            file_id = str(uuid.uuid4())
            # Replace path separators with underscores to flatten the filename
            flattened_filename = file.filename.replace('/', '_').replace('\\', '_')
            safe_filename = f"{file_id}_{flattened_filename}"
            file_path = UPLOAD_DIR / safe_filename
            
            # Save file
            with open(file_path, "wb") as buffer:
                content = await file.read()
                buffer.write(content)
            
            # Store file info
            file_info = UploadedFile(
                id=file_id,
                originalName=file.filename,
                fileName=safe_filename,
                path=str(file_path),
                size=len(content),
                mimeType=file.content_type or "application/octet-stream",
                uploadedAt=datetime.now().isoformat()
            )
            
            uploaded_file_objects.append(file_info)
            uploaded_files[file_id] = str(file_path)
        
        logger.info(f"Successfully uploaded {len(uploaded_file_objects)} files")
        
        return FileUploadResponse(
            success=True,
            files=uploaded_file_objects,
            message=f"Successfully uploaded {len(uploaded_file_objects)} file(s)"
        )
        
    except Exception as e:
        logger.error(f"File upload error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {str(e)}"
        )

@app.post("/api/scanner/scan", response_model=ScanStartResponse)
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    """Start a security scan."""
    if not config.files or len(config.files) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files provided for scanning"
        )
    
    scan_id = str(uuid.uuid4())
    scan_start_time = datetime.now()
    
    # Create scan record in database
    scan_record = {
        "id": scan_id,
        "status": "running",
        "progress": 0,
        "startTime": scan_start_time.isoformat(),
        "endTime": None,
        "files": config.files,
        "config": config.model_dump() if hasattr(config, 'model_dump') else config.dict(),
        "results": None,
        "error": None,
        "target_path": f"Upload-{len(config.files)}-files"
    }
    
    # Store in both database and active_scans for compatibility
    db_service.create_scan(scan_record)
    active_scans[scan_id] = scan_record
    save_active_scans()  # Save initial scan state
    
    # Start scan in background
    background_tasks.add_task(run_scan, scan_id, config)
    
    logger.info(f"Started scan {scan_id} with {len(config.files)} files")
    
    return ScanStartResponse(
        success=True,
        scanId=scan_id,
        status="started",
        message="Security scan started successfully",
        estimatedDuration=len(config.files) * 30
    )

@app.get("/api/scanner/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status and progress."""
    if scan_id not in active_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found with ID: {scan_id}"
        )
    
    scan = active_scans[scan_id]
    
    duration = 0
    if scan["endTime"]:
        end_time = datetime.fromisoformat(scan["endTime"])
        start_time = datetime.fromisoformat(scan["startTime"])
        duration = int((end_time - start_time).total_seconds())
    else:
        start_time = datetime.fromisoformat(scan["startTime"])
        duration = int((datetime.now() - start_time).total_seconds())
    
    return {
        "id": scan["id"],
        "status": scan["status"],
        "startTime": scan["startTime"],
        "progress": scan["progress"],
        "files": len(scan["files"]),
        "results": scan["results"],
        "error": scan["error"],
        "duration": duration
    }

@app.post("/api/scanner/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel an ongoing scan."""
    if scan_id not in active_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found with ID: {scan_id}"
        )
    
    scan = active_scans[scan_id]
    
    if scan["status"] in ["completed", "failed"]:
        return {
            "success": False,
            "message": f"Scan already {scan['status']}, cannot cancel",
            "scanId": scan_id,
            "status": scan["status"]
        }
    
    if scan["status"] == "cancelled":
        return {
            "success": True,
            "message": "Scan was already cancelled",
            "scanId": scan_id,
            "status": "cancelled"
        }
    
    # Mark scan as cancelled
    scan["status"] = "cancelled"
    scan["endTime"] = datetime.now().isoformat()
    scan["error"] = "Scan was cancelled by user"
    # Note: Don't remove immediately, let cleanup_completed_scans() handle it after delay
    
    logger.info(f"Scan {scan_id} cancelled by user")
    
    return {
        "success": True,
        "message": "Scan cancelled successfully",
        "scanId": scan_id,
        "status": "cancelled"
    }

@app.get("/api/scanner/results/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get detailed scan results."""
    # Check active_scans first (for recent/running scans)
    scan = None
    if scan_id in active_scans:
        scan = active_scans[scan_id]
    else:
        # Check database for historical scans
        db_scan = db_service.get_scan(scan_id)
        if db_scan:
            scan = db_scan
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan not found with ID: {scan_id}"
        )
    
    if scan.get("status") != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is still running or failed. Status: {scan.get('status', 'unknown')}"
        )
    
    # Format results for API response
    results = scan.get("results")
    if not results and "vulnerabilities" in scan:
        # Build results from database scan data
        results = {
            "vulnerabilities": scan.get("vulnerabilities", []),
            "total_vulnerabilities": scan.get("total_vulnerabilities", 0),
            "files_scanned": scan.get("files_scanned", 0),
            "scan_duration": scan.get("scan_duration", 0),
            "severity_counts": scan.get("severity_counts", {})
        }
    
    return {
        "scanId": scan.get("id"),
        "results": results,
        "summary": scan.get("summary", {
            "totalVulnerabilities": scan.get("total_vulnerabilities", 0),
            "severityBreakdown": scan.get("severity_counts", {}),
            "scanDuration": scan.get("scan_duration", 0)
        }),
        "completedAt": scan.get("endTime") or scan.get("end_time")
    }

@app.get("/api/scanner/active")
async def get_active_scans():
    """Get currently active (running) scans."""
    try:
        # Return running scans from active_scans, but first check for timeouts
        running_scans = []
        stale_scan_ids = []
        
        for scan_id, scan_data in active_scans.items():
            if scan_data.get("status") == "running":
                duration = 0
                if scan_data.get("startTime"):
                    start_time = datetime.fromisoformat(scan_data["startTime"])
                    duration = int((datetime.now() - start_time).total_seconds())
                    
                    # If scan has been running for more than 30 minutes (1800 seconds), mark as failed
                    if duration > 1800:
                        logger.warning(f"Scan {scan_id} has been running for {duration} seconds, marking as failed")
                        scan_data["status"] = "failed"
                        scan_data["error"] = "Scan timeout - exceeded maximum duration"
                        scan_data["endTime"] = datetime.now().isoformat()
                        stale_scan_ids.append(scan_id)
                        # Update database
                        db_service.update_scan(scan_id, {
                            "status": "failed",
                            "endTime": scan_data["endTime"],
                            "error": "Scan timeout - exceeded maximum duration"
                        })
                        continue
                
                running_scans.append({
                    "id": scan_data["id"],
                    "status": scan_data["status"],
                    "startTime": scan_data["startTime"],
                    "progress": scan_data.get("progress", 0),
                    "filesCount": len(scan_data.get("files", [])),
                    "duration": duration,
                    "target_path": scan_data.get("target_path", "uploaded_files")
                })
        
        # Save changes if any stale scans were cleaned up
        if stale_scan_ids:
            save_active_scans()
            logger.info(f"Cleaned up {len(stale_scan_ids)} stale scans: {stale_scan_ids}")
        
        return {"scans": running_scans}
    
    except Exception as e:
        logger.error(f"Error getting active scans: {e}")
        return {"scans": []}

@app.get("/api/scanner/recent")
async def get_recent_scans(limit: int = 10):
    """Get recent scans list."""
    try:
        # Get recent scans from database
        recent_scans = db_service.get_recent_scans(limit)
        
        # Format for frontend
        formatted_scans = []
        for scan in recent_scans:
            duration = None
            if scan.get("end_time") and scan.get("start_time"):
                start_time = datetime.fromisoformat(scan["start_time"])
                end_time = datetime.fromisoformat(scan["end_time"])
                duration = int((end_time - start_time).total_seconds())
            
            formatted_scans.append({
                "id": scan["id"],
                "status": scan["status"],
                "startTime": scan["start_time"],
                "endTime": scan.get("end_time"),
                "filesCount": scan.get("files_scanned", 0),
                "vulnerabilitiesCount": scan.get("total_vulnerabilities", 0),
                "duration": duration
            })
        
        return {"scans": formatted_scans}
    
    except Exception as e:
        logger.error(f"Error getting recent scans: {e}")
        # Fallback to active_scans if database fails
        scans = list(active_scans.values())
        scans.sort(key=lambda x: x["startTime"], reverse=True)
        scans = scans[:limit]
        
        recent_scans = []
        for scan in scans:
            duration = None
            if scan["endTime"]:
                end_time = datetime.fromisoformat(scan["endTime"])
                start_time = datetime.fromisoformat(scan["startTime"])
                duration = int((end_time - start_time).total_seconds())
            
            recent_scans.append({
                "id": scan["id"],
                "status": scan["status"],
                "startTime": scan["startTime"],
                "endTime": scan["endTime"],
                "filesCount": len(scan["files"]),
                "vulnerabilitiesCount": len(scan["results"]["vulnerabilities"]) if scan["results"] else 0,
                "duration": duration
            })
        
        return {"scans": recent_scans}

@app.get("/api/dashboard/metrics")
async def get_dashboard_metrics(days: int = 30):
    """Get dashboard metrics and analytics."""
    try:
        metrics = db_service.get_dashboard_metrics(days)
        return metrics
    except Exception as e:
        logger.error(f"Error getting dashboard metrics: {e}")
        # Return fallback metrics if database fails
        return {
            "overview": {
                "total_scans": 0,
                "successful_scans": 0,
                "failed_scans": 0,
                "cancelled_scans": 0,
                "running_scans": 0,
                "total_vulnerabilities": 0,
                "total_files_scanned": 0,
                "avg_scan_duration": 0
            },
            "vulnerability_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "threat_types": {},
            "time_series": [],
            "recent_activity": [],
            "system_health": {
                "uptime": "99.9%",
                "response_time": "0.0s",
                "error_rate": "0.0%"
            }
        }

@app.get("/api/dashboard/scan-history")
async def get_scan_history(limit: int = 50):
    """Get scan history for dashboard."""
    try:
        history = db_service.get_scan_history(limit)
        return {"scans": history}
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return {"scans": []}

@app.get("/api/dashboard/vulnerability-trends")
async def get_vulnerability_trends(days: int = 7):
    """Get vulnerability trends over time."""
    try:
        metrics = db_service.get_dashboard_metrics(days)
        return {
            "time_series": metrics.get("time_series", []),
            "severity_breakdown": metrics.get("vulnerability_severity", {}),
            "threat_types": metrics.get("threat_types", {})
        }
    except Exception as e:
        logger.error(f"Error getting vulnerability trends: {e}")
        return {
            "time_series": [],
            "severity_breakdown": {},
            "threat_types": {}
        }

async def run_scan(scan_id: str, config: ScanConfig):
    """Run the actual security scan in the background."""
    scan = active_scans.get(scan_id)
    if not scan:
        return
    
    if not SCANNER_AVAILABLE:
        scan["status"] = "failed"
        scan["error"] = "MCP Scanner not available - import failed"
        scan["endTime"] = datetime.now().isoformat()
        save_active_scans()  # Save status change
        logger.error(f"Scan {scan_id} failed: Scanner not available")
        return
    
    try:
        # Update progress
        scan["progress"] = 10
        save_active_scans()  # Save progress
        
        # Prepare file paths for scanning
        file_paths = []
        for file_id in config.files:
            if file_id in uploaded_files:
                file_paths.append(uploaded_files[file_id])
            else:
                # Assume it's already a file path
                file_paths.append(file_id)
        
        if not file_paths:
            scan["status"] = "failed"
            scan["error"] = "No valid file paths found"
            scan["endTime"] = datetime.now().isoformat()
            save_active_scans()  # Save status change
            return
        
        scan["progress"] = 25
        save_active_scans()  # Save progress
        
        logger.info(f"Starting direct scanner on files: {file_paths}")
        
        # Configure scanner modes
        static_only = config.static_only or (config.enableStatic and not config.enableAI)
        ai_only = config.ai_only or (config.enableAI and not config.enableStatic)
        
        # Set API key if provided and AI analysis is enabled - BEFORE scanner initialization
        if config.api_key and not static_only:
            # Set environment variable for AI provider API key
            if config.ai_provider == 'openai':
                os.environ['OPENAI_API_KEY'] = config.api_key
            elif config.ai_provider == 'claude':
                os.environ['ANTHROPIC_API_KEY'] = config.api_key
            elif config.ai_provider == 'gemini':
                os.environ['GEMINI_API_KEY'] = config.api_key
            logger.info(f"Set API key for {config.ai_provider} AI analysis")
        
        # Initialize the scanner with AI provider configuration - AFTER setting environment
        scanner = SecurityScanner(
            ai_provider=config.ai_provider or "openai",
            verbose=config.verbose
        )
        
        scan["progress"] = 40
        
        # Create a temporary directory to scan multiple files
        temp_dir = Path(tempfile.mkdtemp())
        try:
            # Copy files to temp directory for scanning
            copied_files = 0
            for file_path in file_paths:
                if os.path.exists(file_path):
                    shutil.copy2(file_path, temp_dir)
                    copied_files += 1
                    logger.info(f"Copied {file_path} to {temp_dir}")
                else:
                    logger.error(f"File not found: {file_path}")
            
            if copied_files == 0:
                scan["status"] = "failed"
                scan["error"] = "No files could be found for scanning"
                scan["endTime"] = datetime.now().isoformat()
                return
            
            logger.info(f"Successfully copied {copied_files} files to temp directory {temp_dir}")
            
            scan["progress"] = 50
            
            # Run the scan with cancellation support
            def progress_callback(message: str):
                """Progress callback for scanner updates with cancellation check."""
                # Check if scan was cancelled
                if scan.get("status") == "cancelled":
                    raise Exception("Scan was cancelled by user")
                
                logger.info(f"Scan {scan_id}: {message}")
                # Increment progress slowly
                current_progress = scan.get("progress", 50)
                scan["progress"] = min(current_progress + 5, 90)
            
            scan_result = scanner.scan_directory(
                str(temp_dir),
                static_only=static_only,
                ai_only=ai_only,
                progress_callback=progress_callback
            )
            
            scan["progress"] = 95
            
            # Generate JSON report
            report_generator = ReportGenerator()
            json_report = report_generator.generate_json_report(scan_result)
            
            # Parse the JSON report to get structured data
            try:
                scan_results = json.loads(json_report) if isinstance(json_report, str) else scan_result.to_dict()
            except:
                # Fallback to manual conversion
                scan_results = scan_result.to_dict()
            
            scan["status"] = "completed"
            scan["progress"] = 100
            scan["endTime"] = datetime.now().isoformat()
            scan["results"] = scan_results
            scan["summary"] = {
                "totalVulnerabilities": scan_results.get("total_vulnerabilities", len(scan_results.get("vulnerabilities", []))),
                "severityBreakdown": scan_results.get("severity_counts", {}),
                "scanDuration": scan_results.get("scan_duration", 0)
            }
            
            # Save to database and persistent storage
            db_service.complete_scan(scan_id, scan_results)
            db_service.update_scan(scan_id, {
                "status": "completed",
                "progress": 100,
                "endTime": scan["endTime"],
                "scan_duration": scan_results.get("scan_duration", 0)
            })
            
            active_scans[scan_id] = scan
            save_scan_result(scan_id, scan)
            
            # Note: Don't remove immediately, let cleanup_completed_scans() handle it after delay
            
            logger.info(f"Scan {scan_id} completed successfully with {scan['summary']['totalVulnerabilities']} vulnerabilities")
            
        finally:
            # Clean up temp directory
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
        
    except Exception as e:
        scan["status"] = "failed"
        scan["error"] = str(e)
        scan["endTime"] = datetime.now().isoformat()
        # Note: Don't remove immediately, let cleanup_completed_scans() handle it after delay
        
        # Update database
        db_service.update_scan(scan_id, {
            "status": "failed",
            "endTime": scan["endTime"],
            "error": str(e)
        })
        
        logger.error(f"Scan {scan_id} failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
    
    finally:
        # Cleanup uploaded files after scan (with delay)
        await asyncio.sleep(60)  # Wait 1 minute before cleanup
        for file_id in config.files:
            if file_id in uploaded_files:
                file_path = uploaded_files[file_id]
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    del uploaded_files[file_id]
                except Exception as cleanup_error:
                    logger.error(f"Failed to cleanup file {file_path}: {cleanup_error}")

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred"
        }
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )