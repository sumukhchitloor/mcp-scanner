"""Database service for managing scans, vulnerabilities, and dashboard data."""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func, and_
from collections import defaultdict

try:
    from .database import get_db_session, Scan, Vulnerability, DashboardMetric
except ImportError:
    from database import get_db_session, Scan, Vulnerability, DashboardMetric

logger = logging.getLogger(__name__)


class DatabaseService:
    """Service for database operations."""
    
    def __init__(self):
        self.db_session = get_db_session
    
    # Scan operations
    def create_scan(self, scan_data: Dict[str, Any]) -> str:
        """Create a new scan record."""
        with self.db_session() as db:
            scan = Scan(
                id=scan_data["id"],
                target_path=scan_data.get("target_path", ""),
                start_time=datetime.fromisoformat(scan_data["startTime"]) if scan_data.get("startTime") else datetime.utcnow(),
                status=scan_data.get("status", "running"),
                files_scanned=scan_data.get("files", 0) if isinstance(scan_data.get("files"), int) else len(scan_data.get("files", [])),
                ai_provider=scan_data.get("config", {}).get("ai_provider") if scan_data.get("config") else None,
                static_only=scan_data.get("config", {}).get("static_only", False) if scan_data.get("config") else False,
                ai_only=scan_data.get("config", {}).get("ai_only", False) if scan_data.get("config") else False,
                progress=scan_data.get("progress", 0),
                scan_output=json.dumps(scan_data.get("scan_output", []))
            )
            db.add(scan)
            db.commit()
            return scan.id
    
    def update_scan(self, scan_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing scan record."""
        with self.db_session() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return False
            
            for key, value in updates.items():
                if key == "endTime" and value:
                    scan.end_time = datetime.fromisoformat(value)
                elif key == "scan_duration":
                    scan.scan_duration = value
                elif key == "status":
                    scan.status = value
                elif key == "progress":
                    scan.progress = value
                elif key == "error":
                    scan.error_message = value
                elif key == "current_step":
                    scan.current_step = value
                elif key == "scan_output":
                    scan.scan_output = json.dumps(value) if isinstance(value, list) else value
                elif hasattr(scan, key):
                    setattr(scan, key, value)
            
            db.commit()
            return True
    
    def complete_scan(self, scan_id: str, results: Dict[str, Any]) -> bool:
        """Mark scan as completed and store results."""
        with self.db_session() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return False
            
            # Update scan status and timing
            scan.status = "completed"
            scan.end_time = datetime.utcnow()
            if scan.start_time:
                scan.scan_duration = (scan.end_time - scan.start_time).total_seconds()
            scan.progress = 100
            
            # Store vulnerability count and severity breakdown
            vulnerabilities = results.get("vulnerabilities", [])
            scan.total_vulnerabilities = len(vulnerabilities)
            
            # Calculate severity counts
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            vulnerability_type_counts = defaultdict(int)
            
            for vuln_data in vulnerabilities:
                severity = vuln_data.get("severity", "LOW")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                vuln_type = vuln_data.get("type", "other")
                vulnerability_type_counts[vuln_type] += 1
                
                # Create vulnerability record
                vulnerability = Vulnerability(
                    id=vuln_data.get("id", f"{scan_id}_{len(scan.vulnerabilities)}"),
                    scan_id=scan_id,
                    type=vuln_type,
                    severity=severity,
                    file_path=vuln_data.get("file_path", ""),
                    line_number=vuln_data.get("line_number", 0),
                    code_snippet=vuln_data.get("code_snippet", ""),
                    description=vuln_data.get("description", ""),
                    recommendation=vuln_data.get("recommendation", ""),
                    confidence=vuln_data.get("confidence", 75.0),
                    detector=vuln_data.get("detector", "unknown"),
                    rule_name=vuln_data.get("rule_name"),
                    cwe_id=vuln_data.get("cwe_id"),
                    additional_info=json.dumps(vuln_data.get("additional_info", {}))
                )
                db.add(vulnerability)
            
            # Store severity counts
            scan.severity_counts = json.dumps(severity_counts)
            
            db.commit()
            
            # Update dashboard metrics
            self._update_dashboard_metrics(db, scan, severity_counts, vulnerability_type_counts)
            
            return True
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan by ID."""
        with self.db_session() as db:
            scan = db.query(Scan).options(joinedload(Scan.vulnerabilities)).filter(Scan.id == scan_id).first()
            return scan.to_dict() if scan else None
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans."""
        with self.db_session() as db:
            scans = db.query(Scan).order_by(desc(Scan.start_time)).limit(limit).all()
            return [scan.to_dict() for scan in scans]
    
    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get scan history with summary information."""
        with self.db_session() as db:
            scans = db.query(Scan).order_by(desc(Scan.start_time)).limit(limit).all()
            return [{
                "id": scan.id,
                "target_path": scan.target_path,
                "start_time": scan.start_time.isoformat() if scan.start_time else None,
                "end_time": scan.end_time.isoformat() if scan.end_time else None,
                "status": scan.status,
                "duration": scan.scan_duration,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "files_scanned": scan.files_scanned,
                "severity_counts": json.loads(scan.severity_counts) if scan.severity_counts else {},
                "ai_provider": scan.ai_provider
            } for scan in scans]
    
    # Dashboard operations
    def get_dashboard_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Get dashboard metrics for the specified number of days."""
        with self.db_session() as db:
            # Get date range with buffer for timezone issues
            end_date = datetime.utcnow() + timedelta(hours=24)  # Add 24h buffer for future timestamps
            start_date = end_date - timedelta(days=days + 1)    # Add 1 extra day
            
            # Get scans in date range (or all scans if none in range)
            scans = db.query(Scan).filter(
                Scan.start_time >= start_date,
                Scan.start_time <= end_date
            ).all()
            
            # If no scans in date range, get all scans as fallback
            if not scans:
                scans = db.query(Scan).all()
                
            # Get historical comparison data (previous period)
            historical_start = start_date - timedelta(days=days + 1)
            historical_end = start_date
            historical_scans = db.query(Scan).filter(
                Scan.start_time >= historical_start,
                Scan.start_time <= historical_end
            ).all()
            
            # Calculate metrics
            total_scans = len(scans)
            successful_scans = len([s for s in scans if s.status == "completed"])
            failed_scans = len([s for s in scans if s.status == "failed"])
            cancelled_scans = len([s for s in scans if s.status == "cancelled"])
            running_scans = len([s for s in scans if s.status == "running"])
            
            # Vulnerability metrics
            total_vulnerabilities = sum(s.total_vulnerabilities or 0 for s in scans)
            severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            
            for scan in scans:
                if scan.severity_counts:
                    severity_data = json.loads(scan.severity_counts)
                    for severity, count in severity_data.items():
                        if severity in severity_totals:
                            severity_totals[severity] += count
            
            # Get vulnerability details for threat analysis
            vulnerabilities = db.query(Vulnerability).join(Scan).filter(
                Scan.start_time >= start_date,
                Scan.start_time <= end_date
            ).all()
            
            # Threat type analysis
            threat_types = defaultdict(int)
            for vuln in vulnerabilities:
                threat_types[vuln.type] += 1
            
            # Time series data (daily metrics)
            daily_metrics = []
            for i in range(days):
                day = start_date + timedelta(days=i)
                day_scans = [s for s in scans if s.start_time.date() == day.date()]
                day_vulns = sum(s.total_vulnerabilities or 0 for s in day_scans)
                
                daily_metrics.append({
                    "date": day.isoformat(),
                    "scans": len(day_scans),
                    "vulnerabilities": day_vulns,
                    "successful_scans": len([s for s in day_scans if s.status == "completed"])
                })
            
            # File analysis
            total_files_scanned = sum(s.files_scanned or 0 for s in scans)
            # Only use positive scan durations
            valid_durations = [s.scan_duration for s in scans if s.scan_duration and s.scan_duration > 0]
            avg_scan_duration = sum(valid_durations) / max(len(valid_durations), 1) if valid_durations else 30.0
            
            # Calculate historical metrics for trends
            historical_total_scans = len(historical_scans)
            historical_vulnerabilities = sum(s.total_vulnerabilities or 0 for s in historical_scans)
            historical_successful = len([s for s in historical_scans if s.status == "completed"])
            historical_valid_durations = [s.scan_duration for s in historical_scans if s.scan_duration and s.scan_duration > 0]
            historical_avg_duration = (sum(historical_valid_durations) / max(len(historical_valid_durations), 1)) if historical_valid_durations else 30.0
            
            # Calculate trend percentages
            def calculate_trend(current: float, historical: float) -> Dict[str, Any]:
                if historical == 0:
                    return {"value": 0, "is_positive": current >= 0}
                
                change_percent = ((current - historical) / historical) * 100
                return {
                    "value": round(abs(change_percent)),
                    "is_positive": change_percent >= 0
                }
            
            # Calculate security score (100 = perfect, lower = more vulnerabilities)
            current_security_score = max(0, 100 - min(total_vulnerabilities * 2, 100))  # Each vuln reduces score by 2
            historical_security_score = max(0, 100 - min(historical_vulnerabilities * 2, 100))
            
            trends = {
                "total_scans": calculate_trend(total_scans, historical_total_scans),
                "total_vulnerabilities": calculate_trend(total_vulnerabilities, historical_vulnerabilities),
                "avg_scan_duration": calculate_trend(avg_scan_duration, historical_avg_duration),
                "security_score": calculate_trend(current_security_score, historical_security_score)
            }
            
            # Recent activity
            recent_scans = db.query(Scan).order_by(desc(Scan.start_time)).limit(5).all()
            recent_activity = [{
                "id": scan.id,
                "target_path": scan.target_path,
                "timestamp": scan.start_time.isoformat() if scan.start_time else None,
                "status": scan.status,
                "vulnerabilities": scan.total_vulnerabilities or 0,
                "type": "scan_completed" if scan.status == "completed" else "scan_started"
            } for scan in recent_scans]
            
            return {
                "overview": {
                    "total_scans": total_scans,
                    "successful_scans": successful_scans,
                    "failed_scans": failed_scans,
                    "cancelled_scans": cancelled_scans,
                    "running_scans": running_scans,
                    "total_vulnerabilities": total_vulnerabilities,
                    "total_files_scanned": total_files_scanned,
                    "avg_scan_duration": round(avg_scan_duration, 2),
                    "security_score": current_security_score
                },
                "trends": trends,
                "vulnerability_severity": severity_totals,
                "threat_types": dict(threat_types),
                "time_series": daily_metrics,
                "recent_activity": recent_activity,
                "system_health": {
                    "uptime": "99.9%",  # Could be calculated from scan success rates
                    "response_time": f"{round(avg_scan_duration, 1)}s",
                    "error_rate": f"{round((failed_scans / max(total_scans, 1)) * 100, 1)}%"
                }
            }
    
    def _update_dashboard_metrics(self, db: Session, scan: Scan, severity_counts: Dict, type_counts: Dict):
        """Update daily dashboard metrics."""
        today = datetime.utcnow().date()
        
        # Get or create today's metrics
        metric = db.query(DashboardMetric).filter(
            func.date(DashboardMetric.date) == today
        ).first()
        
        if not metric:
            metric = DashboardMetric(
                date=datetime.combine(today, datetime.min.time()),
                total_scans=0,
                successful_scans=0,
                failed_scans=0,
                cancelled_scans=0,
                total_vulnerabilities=0,
                critical_vulnerabilities=0,
                high_vulnerabilities=0,
                medium_vulnerabilities=0,
                low_vulnerabilities=0,
                total_files_scanned=0,
                avg_scan_duration=0.0
            )
            db.add(metric)
        
        # Update scan counts (ensure values are not None)
        metric.total_scans = (metric.total_scans or 0) + 1
        if scan.status == "completed":
            metric.successful_scans = (metric.successful_scans or 0) + 1
        elif scan.status == "failed":
            metric.failed_scans = (metric.failed_scans or 0) + 1
        elif scan.status == "cancelled":
            metric.cancelled_scans = (metric.cancelled_scans or 0) + 1
        
        # Update vulnerability counts
        metric.total_vulnerabilities = (metric.total_vulnerabilities or 0) + sum(severity_counts.values())
        metric.critical_vulnerabilities = (metric.critical_vulnerabilities or 0) + severity_counts.get("CRITICAL", 0)
        metric.high_vulnerabilities = (metric.high_vulnerabilities or 0) + severity_counts.get("HIGH", 0)
        metric.medium_vulnerabilities = (metric.medium_vulnerabilities or 0) + severity_counts.get("MEDIUM", 0)
        metric.low_vulnerabilities = (metric.low_vulnerabilities or 0) + severity_counts.get("LOW", 0)
        
        # Update file metrics
        metric.total_files_scanned = (metric.total_files_scanned or 0) + (scan.files_scanned or 0)
        if scan.scan_duration and (metric.successful_scans or 0) > 0:
            # Update running average
            current_avg = (metric.avg_scan_duration or 0.0) * ((metric.successful_scans or 1) - 1)
            metric.avg_scan_duration = (current_avg + scan.scan_duration) / (metric.successful_scans or 1)
        
        # Update threat type counts
        metric.command_injection_count = (metric.command_injection_count or 0) + type_counts.get("command_injection", 0)
        metric.sql_injection_count = (metric.sql_injection_count or 0) + type_counts.get("sql_injection", 0)
        metric.authentication_count = (metric.authentication_count or 0) + type_counts.get("authentication", 0)
        metric.file_security_count = (metric.file_security_count or 0) + type_counts.get("file_security", 0)
        metric.other_count = (metric.other_count or 0) + type_counts.get("other", 0)
        
        db.commit()
    
    def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old scan data."""
        with self.db_session() as db:
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            # Delete old vulnerabilities first (foreign key constraint)
            old_scans = db.query(Scan).filter(Scan.start_time < cutoff_date).all()
            for scan in old_scans:
                db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).delete()
                db.delete(scan)
            
            # Delete old dashboard metrics
            db.query(DashboardMetric).filter(DashboardMetric.date < cutoff_date).delete()
            
            db.commit()
            logger.info(f"Cleaned up scan data older than {days_to_keep} days")


# Global database service instance
db_service = DatabaseService()