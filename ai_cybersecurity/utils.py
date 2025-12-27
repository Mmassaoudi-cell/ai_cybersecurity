"""
Utility functions and data models for the AI Cybersecurity Library.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from pathlib import Path

class VulnerabilityLevel(Enum):
    """Enumeration of vulnerability severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ModelFramework(Enum):
    """Enumeration of supported ML frameworks."""
    TENSORFLOW = "tensorflow"
    PYTORCH = "pytorch"
    SCIKIT_LEARN = "scikit-learn"
    XGBOOST = "xgboost"
    ONNX = "onnx"
    HUGGINGFACE = "huggingface"
    UNKNOWN = "unknown"

class AgentFramework(Enum):
    """Enumeration of supported AI agent frameworks."""
    LANGCHAIN = "langchain"
    LLAMAINDEX = "llamaindex"
    AUTOGEN = "autogen"
    CREWAI = "crewai"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

class VulnerabilityReport(BaseModel):
    """Data model for vulnerability reports."""
    level: VulnerabilityLevel = Field(..., description="Severity level of the vulnerability")
    title: str = Field(..., description="Title of the vulnerability")
    description: str = Field(..., description="Detailed description of the vulnerability")
    remediation: str = Field(..., description="Recommended remediation steps")
    timestamp: datetime = Field(default_factory=datetime.now, description="When the vulnerability was detected")
    affected_components: List[str] = Field(default_factory=list, description="List of affected components")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier if applicable")
    references: List[str] = Field(default_factory=list, description="Reference links for more information")
    confidence: float = Field(default=1.0, description="Confidence score (0.0-1.0)")
    impact_score: float = Field(default=0.0, description="Estimated impact score")
    exploitability_score: float = Field(default=0.0, description="Estimated exploitability score")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability report to dictionary."""
        return {
            "level": self.level.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat(),
            "affected_components": self.affected_components,
            "cve_id": self.cve_id,
            "references": self.references,
            "confidence": self.confidence,
            "impact_score": self.impact_score,
            "exploitability_score": self.exploitability_score
        }

class ScanResult(BaseModel):
    """Data model for scan results."""
    vulnerabilities: List[VulnerabilityReport] = Field(..., description="List of detected vulnerabilities")
    target_path: str = Field(..., description="Path of the scanned target")
    scan_duration: float = Field(..., description="Duration of the scan in seconds")
    scan_timestamp: datetime = Field(default_factory=datetime.now, description="When the scan was performed")
    scanner_version: str = Field(default="1.0.0", description="Version of the scanner used")
    risk_score: float = Field(default=0.0, description="Overall risk score")
    total_vulnerabilities: int = Field(default=0, description="Total number of vulnerabilities")
    
    def __init__(self, **data):
        super().__init__(**data)
        # Calculate derived fields
        self.total_vulnerabilities = len(self.vulnerabilities)
        self.risk_score = calculate_risk_score(self.vulnerabilities)
    
    def get_vulnerabilities_by_level(self, level: VulnerabilityLevel) -> List[VulnerabilityReport]:
        """Get vulnerabilities filtered by severity level."""
        return [v for v in self.vulnerabilities if v.level == level]
    
    def get_high_risk_vulnerabilities(self) -> List[VulnerabilityReport]:
        """Get high and critical vulnerabilities."""
        return [v for v in self.vulnerabilities if v.level in [VulnerabilityLevel.HIGH, VulnerabilityLevel.CRITICAL]]
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert scan result to summary dictionary."""
        severity_counts = {}
        for level in VulnerabilityLevel:
            severity_counts[level.value] = len(self.get_vulnerabilities_by_level(level))
        
        return {
            "target_path": self.target_path,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "scan_duration": self.scan_duration,
            "total_vulnerabilities": self.total_vulnerabilities,
            "risk_score": self.risk_score,
            "severity_counts": severity_counts,
            "scanner_version": self.scanner_version
        }

def calculate_risk_score(vulnerabilities: List[VulnerabilityReport]) -> float:
    """
    Calculate overall risk score based on vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability reports
        
    Returns:
        Risk score from 0.0 (no risk) to 4.0 (maximum risk)
    """
    if not vulnerabilities:
        return 0.0
    
    # Severity weights
    severity_weights = {
        VulnerabilityLevel.LOW: 0.5,
        VulnerabilityLevel.MEDIUM: 1.0,
        VulnerabilityLevel.HIGH: 2.0,
        VulnerabilityLevel.CRITICAL: 3.0
    }
    
    total_score = 0.0
    max_score = 0.0
    
    for vuln in vulnerabilities:
        weight = severity_weights.get(vuln.level, 0.0)
        confidence = getattr(vuln, 'confidence', 1.0)
        
        # Apply confidence factor
        weighted_score = weight * confidence
        total_score += weighted_score
        max_score += 3.0  # Maximum possible weight
    
    # Normalize to 0-4 scale
    if max_score == 0:
        return 0.0
    
    normalized_score = (total_score / max_score) * 4.0
    
    # Apply diminishing returns for many vulnerabilities
    num_vulns = len(vulnerabilities)
    if num_vulns > 10:
        # Reduce impact for excessive vulnerabilities
        diminishing_factor = 1.0 - (min(num_vulns - 10, 40) * 0.01)
        normalized_score *= diminishing_factor
    
    return min(normalized_score, 4.0)

def categorize_vulnerability(vuln: VulnerabilityReport) -> str:
    """
    Categorize vulnerability into main categories.
    
    Args:
        vuln: Vulnerability report
        
    Returns:
        Category string
    """
    title_lower = vuln.title.lower()
    description_lower = vuln.description.lower()
    
    # Define category patterns
    categories = {
        "serialization": ["serialization", "pickle", "joblib", "deserialization"],
        "injection": ["injection", "prompt", "code execution", "eval", "exec"],
        "authentication": ["authentication", "authorization", "access control", "permission"],
        "communication": ["communication", "encryption", "https", "ssl", "tls"],
        "supply_chain": ["supply chain", "dependency", "package", "import"],
        "malware": ["malicious", "payload", "trojan", "backdoor"],
        "adversarial": ["adversarial", "robustness", "attack", "evasion"],
        "privacy": ["privacy", "data leakage", "information disclosure"],
        "availability": ["availability", "dos", "resource", "memory"],
        "explainability": ["explainability", "interpretability", "transparency"]
    }
    
    for category, keywords in categories.items():
        if any(keyword in title_lower or keyword in description_lower for keyword in keywords):
            return category
    
    return "other"

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    size_index = 0
    size = float(size_bytes)
    
    while size >= 1024.0 and size_index < len(size_names) - 1:
        size /= 1024.0
        size_index += 1
    
    return f"{size:.1f} {size_names[size_index]}"

def format_timestamp(timestamp: datetime) -> str:
    """Format timestamp for display."""
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")

def validate_file_path(file_path: str) -> Path:
    """
    Validate and convert file path.
    
    Args:
        file_path: File path string
        
    Returns:
        Path object
        
    Raises:
        ValueError: If path is invalid
        FileNotFoundError: If file doesn't exist
    """
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")
    
    return path

def get_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculate file hash.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        Hex digest of file hash
    """
    import hashlib
    
    hash_algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    
    if algorithm not in hash_algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    hasher = hash_algorithms[algorithm]()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    
    return hasher.hexdigest()

def extract_imports_from_code(code: str) -> List[str]:
    """
    Extract import statements from Python code.
    
    Args:
        code: Python source code
        
    Returns:
        List of imported modules
    """
    import ast
    
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    
    imports = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    
    return imports

def is_binary_file(file_path: Path) -> bool:
    """
    Check if file is binary.
    
    Args:
        file_path: Path to file
        
    Returns:
        True if file is binary
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            
        # Check for null bytes (common in binary files)
        if b'\x00' in chunk:
            return True
        
        # Check if we can decode as text
        try:
            chunk.decode('utf-8')
            return False
        except UnicodeDecodeError:
            return True
            
    except Exception:
        return True

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe usage.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import re
    
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing whitespace and dots
    filename = filename.strip('. ')
    
    # Ensure filename is not empty
    if not filename:
        filename = "unnamed_file"
    
    return filename

def create_vulnerability_summary(vulnerabilities: List[VulnerabilityReport]) -> Dict[str, Any]:
    """
    Create a summary of vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability reports
        
    Returns:
        Summary dictionary
    """
    if not vulnerabilities:
        return {
            "total": 0,
            "by_severity": {},
            "by_category": {},
            "risk_score": 0.0,
            "most_critical": None
        }
    
    # Count by severity
    severity_counts = {}
    for level in VulnerabilityLevel:
        severity_counts[level.value] = len([v for v in vulnerabilities if v.level == level])
    
    # Count by category
    category_counts = {}
    for vuln in vulnerabilities:
        category = categorize_vulnerability(vuln)
        category_counts[category] = category_counts.get(category, 0) + 1
    
    # Find most critical vulnerability
    critical_vulns = [v for v in vulnerabilities if v.level == VulnerabilityLevel.CRITICAL]
    high_vulns = [v for v in vulnerabilities if v.level == VulnerabilityLevel.HIGH]
    
    most_critical = None
    if critical_vulns:
        most_critical = critical_vulns[0]
    elif high_vulns:
        most_critical = high_vulns[0]
    elif vulnerabilities:
        most_critical = vulnerabilities[0]
    
    return {
        "total": len(vulnerabilities),
        "by_severity": severity_counts,
        "by_category": category_counts,
        "risk_score": calculate_risk_score(vulnerabilities),
        "most_critical": most_critical.title if most_critical else None
    } 