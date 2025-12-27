"""
CLI interface for AI Cybersecurity Scanner
"""

import typer
import json
import time
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Confirm
from rich import box

from ai_cybersecurity.ml_scanner import MLScanner
from ai_cybersecurity.agent_scanner import AgentScanner
from ai_cybersecurity.immunization import ModelImmunizer
from ai_cybersecurity.utils import VulnerabilityLevel, calculate_risk_score, format_timestamp

app = typer.Typer(
    name="ai-cybersecurity",
    help="🛡️ AI Cybersecurity Scanner - Detect vulnerabilities in ML models and AI agents",
    add_completion=False
)
console = Console()

# Color mapping for severity levels
SEVERITY_COLORS = {
    VulnerabilityLevel.LOW: "green",
    VulnerabilityLevel.MEDIUM: "yellow", 
    VulnerabilityLevel.HIGH: "red",
    VulnerabilityLevel.CRITICAL: "bright_red"
}

SEVERITY_ICONS = {
    VulnerabilityLevel.LOW: "🟢",
    VulnerabilityLevel.MEDIUM: "🟡", 
    VulnerabilityLevel.HIGH: "🔴",
    VulnerabilityLevel.CRITICAL: "🚨"
}

@app.command()
def scan_model(
    model_path: str = typer.Argument(..., help="Path to ML model file"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, html"),
    save_report: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output with detailed information")
):
    """🔍 Scan ML model for cybersecurity vulnerabilities."""
    
    model_path_obj = Path(model_path)
    
    if not model_path_obj.exists():
        console.print(f"❌ Error: Model file not found: {model_path}", style="bold red")
        raise typer.Exit(1)
    
    console.print(f"🔍 Scanning ML model: {model_path}", style="bold blue")
    console.print()
    
    # Initialize scanner
    scanner = MLScanner()
    vulnerabilities = []
    
    # Progress tracking
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        
        scan_task = progress.add_task("🔎 Analyzing model...", total=100)
        
        try:
            # Simulate scanning stages
            progress.update(scan_task, advance=20, description="🔎 Detecting framework...")
            time.sleep(0.5)
            
            progress.update(scan_task, advance=30, description="🔎 Checking serialization...")
            time.sleep(0.5)
            
            progress.update(scan_task, advance=25, description="🔎 Scanning for malicious payloads...")
            vulnerabilities = scanner.scan_model(model_path_obj)
            
            progress.update(scan_task, advance=25, description="✅ Scan complete!")
            time.sleep(0.3)
            
        except Exception as e:
            console.print(f"❌ Scanning failed: {str(e)}", style="bold red")
            raise typer.Exit(1)
    
    # Display results
    _display_scan_results(vulnerabilities, output_format, verbose, save_report, "ML Model")

@app.command()
def scan_agent(
    agent_path: str = typer.Argument(..., help="Path to AI agent Python file"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, html"),
    save_report: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output with detailed information")
):
    """🤖 Scan AI agent for cybersecurity vulnerabilities."""
    
    agent_path_obj = Path(agent_path)
    
    if not agent_path_obj.exists():
        console.print(f"❌ Error: Agent file not found: {agent_path}", style="bold red")
        raise typer.Exit(1)
    
    console.print(f"🤖 Scanning AI agent: {agent_path}", style="bold blue")
    console.print()
    
    # Initialize scanner
    scanner = AgentScanner()
    vulnerabilities = []
    
    # Progress tracking
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        
        scan_task = progress.add_task("🤖 Analyzing agent...", total=100)
        
        try:
            progress.update(scan_task, advance=15, description="🤖 Parsing code structure...")
            time.sleep(0.3)
            
            progress.update(scan_task, advance=20, description="🤖 Checking prompt injection...")
            time.sleep(0.4)
            
            progress.update(scan_task, advance=20, description="🤖 Analyzing code execution...")
            time.sleep(0.3)
            
            progress.update(scan_task, advance=20, description="🤖 Checking authorization...")
            time.sleep(0.3)
            
            progress.update(scan_task, advance=15, description="🤖 Scanning dependencies...")
            time.sleep(0.4)
            
            vulnerabilities = scanner.scan_agent(agent_path_obj)
            
            progress.update(scan_task, advance=10, description="✅ Scan complete!")
            time.sleep(0.3)
            
        except Exception as e:
            console.print(f"❌ Scanning failed: {str(e)}", style="bold red")
            raise typer.Exit(1)
    
    # Display results
    _display_scan_results(vulnerabilities, output_format, verbose, save_report, "AI Agent")

@app.command()
def immunize(
    model_path: str = typer.Argument(..., help="Path to ML model file to immunize"),
    protection_level: str = typer.Option("standard", "--level", "-l", help="Protection level: basic, standard, maximum"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-d", help="Output directory for immunized model"),
    force: bool = typer.Option(False, "--force", "-f", help="Force overwrite if immunized model exists"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """🛡️ Immunize an ML model against detected vulnerabilities."""
    
    model_path_obj = Path(model_path)
    
    if not model_path_obj.exists():
        console.print(f"[red]Error:[/red] Model file not found: {model_path}")
        raise typer.Exit(1)
    
    # Check if it's a supported format
    if model_path_obj.suffix.lower() not in ['.pkl', '.pickle', '.joblib']:
        console.print(f"[red]Error:[/red] Unsupported model format. Only .pkl, .pickle, and .joblib files are supported for immunization.")
        raise typer.Exit(1)
    
    # Validate protection level
    if protection_level not in ["basic", "standard", "maximum"]:
        console.print(f"[red]Error:[/red] Invalid protection level. Must be one of: basic, standard, maximum")
        raise typer.Exit(1)
    
    console.print(f"[bold blue]🛡️ AI Cybersecurity Platform - Model Immunization[/bold blue]")
    console.print(f"Model: {model_path}")
    console.print(f"Protection Level: {protection_level}")
    console.print()
    
    # First, scan the model to detect vulnerabilities
    console.print("[bold]Step 1: Scanning model for vulnerabilities...[/bold]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        scan_task = progress.add_task("Scanning model...", total=None)
        
        try:
            scanner = MLScanner()
            vulnerabilities = scanner.scan_model(model_path_obj)
            progress.update(scan_task, description="Scan complete")
        except Exception as e:
            console.print(f"[red]Error during scanning:[/red] {e}")
            raise typer.Exit(1)
    
    if not vulnerabilities:
        console.print("[green]✅ No vulnerabilities found. Model does not need immunization.[/green]")
        return
    
    # Display found vulnerabilities
    console.print(f"[yellow]⚠️ Found {len(vulnerabilities)} vulnerabilities:[/yellow]")
    
    vuln_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
    vuln_table.add_column("Severity", style="bold", width=10)
    vuln_table.add_column("Title", style="bold", width=30)
    vuln_table.add_column("Description", width=50)
    
    for vuln in vulnerabilities:
        severity_color = SEVERITY_COLORS.get(vuln.level, "white")
        icon = SEVERITY_ICONS.get(vuln.level, "❓")
        
        vuln_table.add_row(
            f"{icon} {vuln.level.value.upper()}",
            vuln.title,
            vuln.description[:100] + "..." if len(vuln.description) > 100 else vuln.description
        )
    
    console.print(vuln_table)
    console.print()
    
    # Ask for confirmation
    if not force:
        if not Confirm.ask(f"Proceed with immunization using {protection_level} protection level?"):
            console.print("[yellow]Immunization cancelled.[/yellow]")
            return
    
    # Run immunization
    console.print("[bold]Step 2: Immunizing model...[/bold]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        immunize_task = progress.add_task("Immunizing model...", total=None)
        
        try:
            immunizer = ModelImmunizer()
            result = immunizer.immunize_model(model_path_obj, vulnerabilities, protection_level)
            progress.update(immunize_task, description="Immunization complete")
        except Exception as e:
            console.print(f"[red]Error during immunization:[/red] {e}")
            raise typer.Exit(1)
    
    if result['status'] == 'success':
        console.print("[green]✅ Model immunization completed successfully![/green]")
        console.print()
        
        # Display results
        report = result['report']
        
        results_table = Table(show_header=True, header_style="bold green", box=box.ROUNDED)
        results_table.add_column("Metric", style="bold", width=25)
        results_table.add_column("Value", width=50)
        
        results_table.add_row("Original Model", report['original_model'])
        results_table.add_row("Immunized Model", report['immunized_model'])
        results_table.add_row("Total Vulnerabilities", str(report['total_vulnerabilities']))
        results_table.add_row("Successfully Protected", str(report['successful_protections']))
        results_table.add_row("Protection Rate", f"{report['protection_rate']:.1%}")
        results_table.add_row("Protection Methods", ", ".join(report['protection_methods_applied']))
        
        console.print(results_table)
        
        if verbose:
            console.print("\n[bold]Recommendations:[/bold]")
            for rec in report['recommendations']:
                console.print(f"• {rec}")
        
        console.print(f"\n[green]Immunized model saved to: {result['immunized_path']}[/green]")
    else:
        console.print(f"[red]❌ Immunization failed:[/red] {result.get('error', 'Unknown error')}")
        raise typer.Exit(1)

@app.command()
def info():
    """ℹ️ Display platform information and version."""
    
    info_panel = Panel.fit(
        """[bold blue]AI Cybersecurity Platform v1.0[/bold blue]

A Unified Platform for Automated Cybersecurity Vulnerability Assessment
in Machine Learning Models and AI Agents

[bold]Authors:[/bold] Mohamed Massaoudi, Katherine R. Davis
[bold]Institution:[/bold] Texas A&M University
[bold]License:[/bold] MIT

[bold]Supported Formats:[/bold]
• ML Models: .pkl, .joblib, .h5, .hdf5, .onnx, .pth, .pt
• AI Agents: .py (Python files)

[bold]Scan Capabilities:[/bold]
• Insecure serialization detection
• Malicious payload scanning
• Adversarial robustness testing
• Prompt injection analysis
• Code execution vulnerabilities
• Supply chain security assessment

[bold]Immunization Features:[/bold]
• Adversarial training protection
• Secure serialization wrappers
• Input validation layers
• Differential privacy mechanisms
• Model encryption and integrity checks

For help with specific commands, use: ai-cybersecurity [COMMAND] --help
""",
        title="Platform Information",
        border_style="blue"
    )
    
    console.print(info_panel)

def _display_scan_results(vulnerabilities: List, output_format: str, verbose: bool, save_report: Optional[str], scan_type: str):
    """Display scan results in the specified format."""
    
    total_vulns = len(vulnerabilities)
    risk_score = calculate_risk_score(vulnerabilities)
    
    # Count by severity
    severity_counts = {}
    for level in VulnerabilityLevel:
        severity_counts[level.value] = len([v for v in vulnerabilities if v.level == level])
    
    # Display summary
    _display_summary(total_vulns, risk_score, severity_counts, scan_type)
    
    if total_vulns == 0:
        console.print("✅ No vulnerabilities found! The file appears to be secure.", style="bold green")
        return
    
    # Display detailed results
    if output_format == "table":
        _display_table(vulnerabilities, verbose)
    elif output_format == "json":
        _display_json(vulnerabilities, save_report)
    elif output_format == "html":
        _generate_html_report(vulnerabilities, save_report)
    
    # Save report if requested and not already saved
    if save_report and output_format == "table":
        _save_report(vulnerabilities, save_report, "text")

def _display_summary(total_vulns: int, risk_score: float, severity_counts: dict, scan_type: str):
    """Display scan summary."""
    
    # Risk level based on score
    if risk_score >= 3.0:
        risk_style = "bold red"
        risk_icon = "🚨"
        risk_text = "CRITICAL"
    elif risk_score >= 2.0:
        risk_style = "bold orange"
        risk_icon = "⚠️"
        risk_text = "HIGH"
    elif risk_score >= 1.0:
        risk_style = "bold yellow"
        risk_icon = "🟡"
        risk_text = "MEDIUM"
    else:
        risk_style = "bold green"
        risk_icon = "✅"
        risk_text = "LOW"
    
    summary_content = f"""[bold]{scan_type} Scan Summary[/bold]

[bold]Total Vulnerabilities:[/bold] {total_vulns}
[bold]Risk Score:[/bold] [{risk_style}]{risk_score:.2f}/4.0 ({risk_icon} {risk_text})[/{risk_style}]

[bold]By Severity:[/bold]
• Critical: [bright_red]{severity_counts.get('critical', 0)}[/bright_red]
• High: [red]{severity_counts.get('high', 0)}[/red]
• Medium: [yellow]{severity_counts.get('medium', 0)}[/yellow]
• Low: [green]{severity_counts.get('low', 0)}[/green]
"""
    
    summary_panel = Panel(summary_content, title="Scan Results", border_style="blue")
    console.print(summary_panel)
    console.print()

def _display_table(vulnerabilities: List, verbose: bool):
    """Display vulnerabilities in table format."""
    
    table = Table(title="Vulnerability Details", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Title", style="bold", width=30)
    table.add_column("Description", width=50)
    
    if verbose:
        table.add_column("Remediation", width=40)
        table.add_column("References", width=30)
    
    for vuln in vulnerabilities:
        # Get severity color and icon
        color = SEVERITY_COLORS.get(vuln.level, "white")
        icon = SEVERITY_ICONS.get(vuln.level, "")
        
        severity_text = f"[{color}]{icon} {vuln.level.value.upper()}[/{color}]"
        
        # Truncate long text for table display
        description = (vuln.description[:100] + "...") if len(vuln.description) > 100 else vuln.description
        
        if verbose:
            remediation = (vuln.remediation[:80] + "...") if len(vuln.remediation) > 80 else vuln.remediation
            references = ", ".join(vuln.references[:2]) if vuln.references else "N/A"
            if len(vuln.references) > 2:
                references += "..."
            
            table.add_row(severity_text, vuln.title, description, remediation, references)
        else:
            table.add_row(severity_text, vuln.title, description)
    
    console.print(table)

def _display_json(vulnerabilities: List, save_path: Optional[str] = None):
    """Display vulnerabilities in JSON format."""
    
    from datetime import datetime
    
    report_data = {
        "scan_timestamp": datetime.now().isoformat(),
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": [
            {
                "level": v.level.value,
                "title": v.title,
                "description": v.description,
                "remediation": v.remediation,
                "timestamp": format_timestamp(v.timestamp),
                "affected_components": v.affected_components,
                "cve_id": v.cve_id,
                "references": v.references,
                "confidence": v.confidence
            }
            for v in vulnerabilities
        ]
    }
    
    json_output = json.dumps(report_data, indent=2)
    
    if save_path:
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(json_output)
        console.print(f"✅ JSON report saved to: {save_path}", style="bold green")
    else:
        console.print(json_output)

def _generate_html_report(vulnerabilities: List, save_path: Optional[str] = None):
    """Generate HTML report."""
    from datetime import datetime
    
    if not save_path:
        save_path = f"ai_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    # Simple HTML template
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI Cybersecurity Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .vulnerability {{ margin-bottom: 20px; padding: 15px; border-radius: 5px; }}
        .critical {{ background: #ffebee; border-left: 5px solid #f44336; }}
        .high {{ background: #fff3e0; border-left: 5px solid #ff9800; }}
        .medium {{ background: #f3e5f5; border-left: 5px solid #9c27b0; }}
        .low {{ background: #e8f5e8; border-left: 5px solid #4caf50; }}
        .title {{ font-weight: bold; font-size: 1.1em; margin-bottom: 10px; }}
        .description {{ margin-bottom: 10px; }}
        .remediation {{ font-style: italic; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI Cybersecurity Scan Report</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
        <p><strong>Risk Score:</strong> {calculate_risk_score(vulnerabilities):.2f}/4.0</p>
    </div>
    
    <h2>Detailed Findings</h2>
"""
    
    for vuln in vulnerabilities:
        html_content += f"""
    <div class="vulnerability {vuln.level.value}">
        <div class="title">{vuln.level.value.upper()}: {vuln.title}</div>
        <div class="description">{vuln.description}</div>
        <div class="remediation"><strong>Remediation:</strong> {vuln.remediation}</div>
    </div>
"""
    
    html_content += """
</body>
</html>
"""
    
    with open(save_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    console.print(f"✅ HTML report saved to: {save_path}", style="bold green")

def _save_report(vulnerabilities: List, save_path: str, format_type: str):
    """Save report to file."""
    
    try:
        if format_type == "text":
            with open(save_path, 'w', encoding='utf-8') as f:
                from datetime import datetime
                
                f.write("AI CYBERSECURITY SCAN REPORT\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n")
                f.write(f"Risk Score: {calculate_risk_score(vulnerabilities):.2f}/4.0\n\n")
                
                f.write("DETAILED FINDINGS:\n")
                f.write("-" * 20 + "\n\n")
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"{i}. {vuln.level.value.upper()}: {vuln.title}\n")
                    f.write(f"   Description: {vuln.description}\n")
                    f.write(f"   Remediation: {vuln.remediation}\n\n")
        
        console.print(f"✅ Report saved to: {save_path}", style="bold green")
        
    except Exception as e:
        console.print(f"❌ Failed to save report: {str(e)}", style="bold red")

if __name__ == "__main__":
    app() 