"""
AI Agent Vulnerability Scanner Module
"""

import ast
from pathlib import Path
from typing import Dict, List, Optional, Union
import re
from pydantic import BaseModel

from ai_cybersecurity.utils import VulnerabilityLevel, VulnerabilityReport
from ai_cybersecurity.integration import (
    PromptInjectionDetector,
    CodeExecutionAnalyzer,
    AuthorizationChecker,
    AgentIdentityVerifier,
    GoalManipulationDetector,
    CommunicationSecurityAnalyzer,
    ResourceManager,
    SupplyChainScanner,
)

class AgentScanner:
    """Scanner for AI agent vulnerabilities."""
    
    def __init__(self):
        self.prompt_detector = PromptInjectionDetector()
        self.code_analyzer = CodeExecutionAnalyzer()
        self.auth_checker = AuthorizationChecker()
        self.identity_verifier = AgentIdentityVerifier()
        self.goal_detector = GoalManipulationDetector()
        self.comm_analyzer = CommunicationSecurityAnalyzer()
        self.resource_manager = ResourceManager()
        self.supply_chain_scanner = SupplyChainScanner()
    
    def scan_agent(self, agent_path: Union[str, Path]) -> List[VulnerabilityReport]:
        """
        Scan an AI agent for vulnerabilities.
        
        Args:
            agent_path: Path to the agent code file
            
        Returns:
            List of vulnerability reports
        """
        agent_path = Path(agent_path)
        vulnerabilities = []
        
        if not agent_path.exists():
            raise FileNotFoundError(f"Agent file not found: {agent_path}")
        
        # Parse the agent code
        with open(agent_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.HIGH,
                    title="Syntax Error in Agent Code",
                    description=f"Agent code contains syntax errors: {str(e)}",
                    remediation="Fix syntax errors in the agent code",
                    affected_components=[str(agent_path)]
                )
            )
            return vulnerabilities
        
        # Check for prompt injection vulnerabilities
        prompt_vulns = self._check_prompt_injection(tree)
        vulnerabilities.extend(prompt_vulns)
        
        # Check for unsafe code execution
        code_vulns = self._check_unsafe_code_execution(tree)
        vulnerabilities.extend(code_vulns)
        
        # Check authorization and access controls
        auth_vulns = self._check_authorization(tree)
        vulnerabilities.extend(auth_vulns)
        
        # Check agent identity and authentication
        identity_vulns = self._check_agent_identity(tree)
        vulnerabilities.extend(identity_vulns)
        
        # Check goal manipulation vulnerabilities
        goal_vulns = self._check_goal_manipulation(tree)
        vulnerabilities.extend(goal_vulns)
        
        # Check inter-agent communication
        comm_vulns = self._check_communication_security(tree)
        vulnerabilities.extend(comm_vulns)
        
        # Check resource management
        resource_vulns = self._check_resource_management(tree)
        vulnerabilities.extend(resource_vulns)
        
        # Check supply chain
        supply_vulns = self._check_supply_chain(agent_path)
        vulnerabilities.extend(supply_vulns)
        
        return vulnerabilities
    
    def _check_prompt_injection(self, tree: ast.AST) -> List[VulnerabilityReport]:
        """Check for prompt injection vulnerabilities."""
        vulnerabilities = []
        results = self.prompt_detector.analyze(tree)
        
        if results.get("has_injection_risk", False):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.HIGH,
                    title="Prompt Injection Vulnerability",
                    description=results.get("description", "Potential prompt injection vulnerability detected"),
                    remediation="Implement input sanitization and prompt validation",
                    affected_components=["prompt_handling"],
                    references=[
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        "https://github.com/leondz/garak"
                    ]
                )
            )
        
        return vulnerabilities
    
    def _check_unsafe_code_execution(self, tree: ast.AST) -> List[VulnerabilityReport]:
        """Check for unsafe code execution patterns."""
        vulnerabilities = []
        results = self.code_analyzer.analyze(tree)
        
        if results.get("has_unsafe_execution", False):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.CRITICAL,
                    title="Unsafe Code Execution",
                    description=results.get("description", "Unsafe code execution patterns detected"),
                    remediation="Replace eval() and exec() with safer alternatives",
                    affected_components=["code_execution"],
                    references=[
                        "https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html",
                        "https://docs.python.org/3/library/functions.html#eval"
                    ]
                )
            )
        
        return vulnerabilities
    
    def _check_authorization(self, tree: ast.AST) -> List[VulnerabilityReport]:
        """Check authorization and access controls."""
        vulnerabilities = []
        results = self.auth_checker.analyze(tree)
        
        if not results.get("has_proper_auth", True):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.HIGH,
                    title="Missing Authorization Controls",
                    description=results.get("description", "Missing or inadequate authorization controls"),
                    remediation="Implement proper RBAC and access control mechanisms",
                    affected_components=["authorization"],
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
                    ]
                )
            )
        
        return vulnerabilities
    
    def _check_agent_identity(self, tree: ast.AST) -> List[VulnerabilityReport]:
        """Check agent identity and authentication."""
        vulnerabilities = []
        results = self.identity_verifier.analyze(tree)
        
        if not results.get("has_proper_identity", True):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.HIGH,
                    title="Weak Agent Identity Verification",
                    description=results.get("description", "Weak or missing agent identity verification"),
                    remediation="Implement strong agent authentication and identity verification",
                    affected_components=["identity_verification"],
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ]
                )
            )
        
        return vulnerabilities
    
    def _check_goal_manipulation(self, tree: ast.AST) -> List[VulnerabilityReport]:
        """Check for goal manipulation vulnerabilities."""
        vulnerabilities = []
        results = self.goal_detector.analyze(tree)
        
        if results.get("has_goal_manipulation", False):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.HIGH,
                    title="Goal Manipulation Vulnerability",
                    description=results.get("description", "Potential goal manipulation vulnerability detected"),
                    remediation="Implement goal validation and integrity checks",
                    affected_components=["goal_management"],
                    references=[
                        "https://arxiv.org/abs/1606.06565",  # Concrete Problems in AI Safety
                        "https://ai-alignment.com/"
                    ]
                )
            )
        
        return vulnerabilities
    
    def _check_communication_security(self, tree: ast.AST) -> List[VulnerabilityReport]:
        """Check inter-agent communication security."""
        vulnerabilities = []
        results = self.comm_analyzer.analyze(tree)
        
        if not results.get("is_secure", True):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.MEDIUM,
                    title="Insecure Inter-Agent Communication",
                    description=results.get("description", "Insecure inter-agent communication detected"),
                    remediation="Implement secure communication channels and message validation",
                    affected_components=["communication"],
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                    ]
                )
            )
        
        return vulnerabilities
    
    def _check_resource_management(self, tree: ast.AST) -> List[VulnerabilityReport]:
        """Check resource management and DoS protection."""
        vulnerabilities = []
        results = self.resource_manager.analyze(tree)
        
        if not results.get("has_proper_management", True):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.MEDIUM,
                    title="Insufficient Resource Management",
                    description=results.get("description", "Insufficient resource management detected"),
                    remediation="Implement rate limiting and resource quotas",
                    affected_components=["resource_management"],
                    references=[
                        "https://owasp.org/www-community/attacks/Denial_of_Service",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
                    ]
                )
            )
        
        return vulnerabilities
    
    def _check_supply_chain(self, agent_path: Path) -> List[VulnerabilityReport]:
        """Check supply chain vulnerabilities."""
        vulnerabilities = []
        results = self.supply_chain_scanner.scan(agent_path)
        
        if results.get("has_vulnerabilities", False):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.HIGH,
                    title="Supply Chain Vulnerabilities",
                    description=results.get("description", "Supply chain vulnerabilities detected"),
                    remediation="Update dependencies and verify third-party components",
                    affected_components=["dependencies"],
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
                        "https://github.com/advisories"
                    ]
                )
            )
        
        return vulnerabilities 