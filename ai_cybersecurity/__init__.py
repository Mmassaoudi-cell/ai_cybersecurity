"""
AI Cybersecurity Platform - A unified platform for automated cybersecurity vulnerability assessment
in Machine Learning models and AI agents.

This is the executable version of the AI Cybersecurity Library.
"""

__version__ = "1.0.0"
__author__ = "Mohamed Massaoudi, Katherine R. Davis"
__email__ = "mohamed.massaoudi@tamu.edu"

from ai_cybersecurity.ml_scanner import MLScanner
from ai_cybersecurity.agent_scanner import AgentScanner
from ai_cybersecurity.reporting import Reporter
from ai_cybersecurity.utils import VulnerabilityLevel, VulnerabilityReport
from ai_cybersecurity.immunization import ModelImmunizer
from ai_cybersecurity.cli import app as cli_app

__all__ = [
    "MLScanner", 
    "AgentScanner", 
    "Reporter", 
    "VulnerabilityLevel", 
    "VulnerabilityReport",
    "ModelImmunizer",
    "cli_app"
] 