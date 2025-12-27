"""
Reporting module for generating vulnerability reports.
"""

import json
from pathlib import Path
from typing import List, Optional, Union
from datetime import datetime
import jinja2
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ai_cybersecurity.utils import (
    VulnerabilityReport,
    ScanResult,
    VulnerabilityLevel,
    format_timestamp,
    calculate_risk_score,
)

class Reporter:
    """Generates vulnerability reports in various formats."""
    
    def __init__(self):
        self.console = Console()
        self.template_loader = jinja2.FileSystemLoader(searchpath="./templates")
        self.template_env = jinja2.Environment(loader=self.template_loader)
    
    def generate_report(
        self,
        scan_result: ScanResult,
        format: str = "json",
        output_path: Optional[Union[str, Path]] = None
    ) -> str:
        """
        Generate a vulnerability report.
        
        Args:
            scan_result: Result of the security scan
            format: Output format (json, html, or text)
            output_path: Path to save the report (optional)
            
        Returns:
            Generated report as string
        """
        if format == "json":
            report = self._generate_json_report(scan_result)
        elif format == "html":
            report = self._generate_html_report(scan_result)
        else:
            report = self._generate_text_report(scan_result)
        
        if output_path:
            output_path = Path(output_path)
            output_path.write_text(report)
        
        return report
    
    def _generate_json_report(self, scan_result: ScanResult) -> str:
        """Generate JSON report."""
        report_data = {
            "scan_timestamp": format_timestamp(scan_result.scan_timestamp),
            "target_path": scan_result.target_path,
            "scan_duration": scan_result.scan_duration,
            "total_vulnerabilities": scan_result.total_vulnerabilities,
            "risk_score": calculate_risk_score(scan_result.vulnerabilities),
            "vulnerabilities": [
                {
                    "level": v.level.value,
                    "title": v.title,
                    "description": v.description,
                    "remediation": v.remediation,
                    "timestamp": format_timestamp(v.timestamp),
                    "affected_components": v.affected_components,
                    "cve_id": v.cve_id,
                    "references": v.references
                }
                for v in scan_result.vulnerabilities
            ]
        }
        return json.dumps(report_data, indent=2)
    
    def _generate_html_report(self, scan_result: ScanResult) -> str:
        """Generate HTML report."""
        template = self.template_env.get_template("report.html")
        return template.render(
            scan_result=scan_result,
            format_timestamp=format_timestamp,
            calculate_risk_score=calculate_risk_score
        )
    
    def _generate_text_report(self, scan_result: ScanResult) -> str:
        """Generate text report using Rich."""
        # Create summary panel
        summary = Panel(
            f"Scan completed at {format_timestamp(scan_result.scan_timestamp)}\n"
            f"Target: {scan_result.target_path}\n"
            f"Duration: {scan_result.scan_duration:.2f}s\n"
            f"Total vulnerabilities: {scan_result.total_vulnerabilities}\n"
            f"Risk score: {calculate_risk_score(scan_result.vulnerabilities):.2f}",
            title="Scan Summary"
        )
        
        # Create vulnerabilities table
        table = Table(title="Vulnerabilities")
        table.add_column("Level", style="bold")
        table.add_column("Title")
        table.add_column("Description")
        table.add_column("Remediation")
        
        for vuln in scan_result.vulnerabilities:
            level_style = {
                VulnerabilityLevel.LOW: "green",
                VulnerabilityLevel.MEDIUM: "yellow",
                VulnerabilityLevel.HIGH: "red",
                VulnerabilityLevel.CRITICAL: "bold red"
            }[vuln.level]
            
            table.add_row(
                f"[{level_style}]{vuln.level.value}[/]",
                vuln.title,
                vuln.description,
                vuln.remediation
            )
        
        # Combine into final report
        with self.console.capture() as capture:
            self.console.print(summary)
            self.console.print(table)
        
        return capture.get() 