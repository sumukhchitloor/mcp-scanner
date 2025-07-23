"""Database setup and models for MCP Security Scanner."""

import os
from datetime import datetime
from typing import List, Optional
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy import JSON as GenericJSON
import json

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./mcp_security.db")
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class Scan(Base):
    """Database model for security scans."""
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True, index=True)
    target_path = Column(String, nullable=False)
    start_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    scan_duration = Column(Float, nullable=True)  # in seconds
    status = Column(String, nullable=False, default="running")  # running, completed, failed, cancelled
    files_scanned = Column(Integer, default=0)
    files_skipped = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    
    # Scan configuration
    ai_provider = Column(String, nullable=True)
    ai_model = Column(String, nullable=True)
    static_only = Column(Boolean, default=False)
    ai_only = Column(Boolean, default=False)
    
    # Progress tracking
    progress = Column(Integer, default=0)  # 0-100
    current_step = Column(String, nullable=True)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    # Results summary as JSON
    severity_counts = Column(Text, nullable=True)  # JSON string
    scan_output = Column(Text, nullable=True)  # JSON array of log messages
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    def to_dict(self):
        """Convert scan to dictionary."""
        return {
            "id": self.id,
            "target_path": self.target_path,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "scan_duration": self.scan_duration,
            "status": self.status,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "total_vulnerabilities": self.total_vulnerabilities,
            "ai_provider": self.ai_provider,
            "ai_model": self.ai_model,
            "static_only": self.static_only,
            "ai_only": self.ai_only,
            "progress": self.progress,
            "current_step": self.current_step,
            "error_message": self.error_message,
            "severity_counts": json.loads(self.severity_counts) if self.severity_counts else {},
            "scan_output": json.loads(self.scan_output) if self.scan_output else [],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities] if self.vulnerabilities else []
        }


class Vulnerability(Base):
    """Database model for individual vulnerabilities."""
    __tablename__ = "vulnerabilities"
    
    id = Column(String, primary_key=True, index=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    
    # Core vulnerability info
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False)
    code_snippet = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    
    # Detection info
    confidence = Column(Float, nullable=False, default=75.0)
    detector = Column(String, nullable=False)  # static_analyzer, ai_analyzer
    rule_name = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    
    # Additional metadata as JSON
    additional_info = Column(Text, nullable=True)  # JSON string
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    
    def to_dict(self):
        """Convert vulnerability to dictionary."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "type": self.type,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "description": self.description,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "detector": self.detector,
            "rule_name": self.rule_name,
            "cwe_id": self.cwe_id,
            "additional_info": json.loads(self.additional_info) if self.additional_info else {},
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class DashboardMetric(Base):
    """Database model for dashboard metrics over time."""
    __tablename__ = "dashboard_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    date = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Scan metrics
    total_scans = Column(Integer, default=0)
    successful_scans = Column(Integer, default=0)
    failed_scans = Column(Integer, default=0)
    cancelled_scans = Column(Integer, default=0)
    
    # Vulnerability metrics
    total_vulnerabilities = Column(Integer, default=0)
    critical_vulnerabilities = Column(Integer, default=0)
    high_vulnerabilities = Column(Integer, default=0)
    medium_vulnerabilities = Column(Integer, default=0)
    low_vulnerabilities = Column(Integer, default=0)
    
    # File metrics
    total_files_scanned = Column(Integer, default=0)
    avg_scan_duration = Column(Float, default=0.0)
    
    # Threat types
    command_injection_count = Column(Integer, default=0)
    sql_injection_count = Column(Integer, default=0)
    authentication_count = Column(Integer, default=0)
    file_security_count = Column(Integer, default=0)
    other_count = Column(Integer, default=0)
    
    def to_dict(self):
        """Convert dashboard metric to dictionary."""
        return {
            "id": self.id,
            "date": self.date.isoformat() if self.date else None,
            "total_scans": self.total_scans,
            "successful_scans": self.successful_scans,
            "failed_scans": self.failed_scans,
            "cancelled_scans": self.cancelled_scans,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_vulnerabilities": self.critical_vulnerabilities,
            "high_vulnerabilities": self.high_vulnerabilities,
            "medium_vulnerabilities": self.medium_vulnerabilities,
            "low_vulnerabilities": self.low_vulnerabilities,
            "total_files_scanned": self.total_files_scanned,
            "avg_scan_duration": self.avg_scan_duration,
            "command_injection_count": self.command_injection_count,
            "sql_injection_count": self.sql_injection_count,
            "authentication_count": self.authentication_count,
            "file_security_count": self.file_security_count,
            "other_count": self.other_count
        }


# Database utility functions
def get_db() -> Session:
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)


def get_db_session() -> Session:
    """Get a database session for direct use."""
    return SessionLocal()