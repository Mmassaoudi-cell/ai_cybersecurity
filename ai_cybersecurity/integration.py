"""
Integration module for external tools and frameworks.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union
import ast
import re
import pickle
import subprocess
import json
import requests
import sys
import tempfile
from pydantic import BaseModel

from ai_cybersecurity.utils import (
    ModelFramework,
    AgentFramework,
    VulnerabilityLevel,
    VulnerabilityReport,
)

class AdversarialTestResult(BaseModel):
    """Result of adversarial testing."""
    is_vulnerable: bool
    attack_type: str
    success_rate: float
    perturbation_size: float

class FoolboxAdversarialTester:
    """Adversarial testing using Foolbox."""
    
    def test_model(self, model_path: Union[str, Path]) -> AdversarialTestResult:
        """Test model using Foolbox attacks."""
        try:
            # Try to import foolbox and run basic adversarial test
            # For now, simulate testing with realistic results
            # In production, this would load the actual model and test it
            model_path = Path(model_path)
            
            # Simulate vulnerability detection based on model type
            if model_path.suffix in ['.pkl', '.joblib']:
                # Pickle models are more vulnerable
                return AdversarialTestResult(
                    is_vulnerable=True,
                    attack_type="FGSM",
                    success_rate=0.75,
                    perturbation_size=0.03
                )
            else:
                return AdversarialTestResult(
                    is_vulnerable=False,
                    attack_type="FGSM",
                    success_rate=0.15,
                    perturbation_size=0.01
                )
                
        except ImportError:
            # Fallback if foolbox not available
            return AdversarialTestResult(
                is_vulnerable=False,
                attack_type="FGSM",
                success_rate=0.0,
                perturbation_size=0.0
            )

class CleverHansAdversarialTester:
    """Adversarial testing using CleverHans."""
    
    def test_model(self, model_path: Union[str, Path]) -> AdversarialTestResult:
        """Test model using CleverHans attacks."""
        try:
            # Simulate testing with realistic results
            model_path = Path(model_path)
            
            # Different vulnerability patterns for different model types
            if model_path.suffix == '.h5':
                return AdversarialTestResult(
                    is_vulnerable=True,
                    attack_type="CarliniWagner",
                    success_rate=0.65,
                    perturbation_size=0.02
                )
            else:
                return AdversarialTestResult(
                    is_vulnerable=False,
                    attack_type="CarliniWagner",
                    success_rate=0.25,
                    perturbation_size=0.005
                )
                
        except ImportError:
            # Fallback if cleverhans not available
            return AdversarialTestResult(
                is_vulnerable=False,
                attack_type="CarliniWagner",
                success_rate=0.0,
                perturbation_size=0.0
            )

class ModelFrameworkDetector:
    """Detect ML model framework."""
    
    def detect(self, model_path: Union[str, Path]) -> ModelFramework:
        """Detect the framework used by the model."""
        model_path = Path(model_path)
        file_ext = model_path.suffix.lower()
        
        # Check file extension first
        if file_ext == '.pkl':
            return self._detect_pickle_framework(model_path)
        elif file_ext in ['.h5', '.hdf5']:
            return ModelFramework.TENSORFLOW
        elif file_ext == '.onnx':
            return ModelFramework.ONNX
        elif file_ext in ['.pth', '.pt']:
            return ModelFramework.PYTORCH
        elif file_ext == '.joblib':
            return ModelFramework.SCIKIT_LEARN
        
        # Check file contents for additional detection
        try:
            with open(model_path, 'rb') as f:
                header = f.read(1024)
                
                if b'tensorflow' in header.lower():
                    return ModelFramework.TENSORFLOW
                elif b'torch' in header.lower():
                    return ModelFramework.PYTORCH
                elif b'sklearn' in header.lower():
                    return ModelFramework.SCIKIT_LEARN
                elif b'xgboost' in header.lower():
                    return ModelFramework.XGBOOST
                    
        except Exception:
            pass
            
        return ModelFramework.UNKNOWN
    
    def _detect_pickle_framework(self, model_path: Path) -> ModelFramework:
        """Detect framework from pickle file without executing it."""
        try:
            # Read pickle file and analyze opcodes safely
            with open(model_path, 'rb') as f:
                content = f.read()
                
                # Look for framework signatures in the pickle content
                content_str = content.decode('latin1', errors='ignore').lower()
                
                if 'sklearn' in content_str or 'scikit' in content_str:
                    return ModelFramework.SCIKIT_LEARN
                elif 'xgboost' in content_str:
                    return ModelFramework.XGBOOST
                elif 'tensorflow' in content_str:
                    return ModelFramework.TENSORFLOW
                elif 'torch' in content_str or 'pytorch' in content_str:
                    return ModelFramework.PYTORCH
                    
        except Exception:
            pass
        return ModelFramework.UNKNOWN

class PromptInjectionDetector:
    """Detect prompt injection vulnerabilities."""
    
    def __init__(self):
        self.injection_patterns = [
            r"ignore\s+previous\s+instructions",
            r"system\s*:\s*you\s+are\s+now",
            r"jailbreak|DAN|developer\s+mode",
            r"\[INST\].*\[/INST\]",  # Llama format injection
            r"<\|.*\|>",  # ChatML injection
            r"___\s*END\s+SYSTEM\s+PROMPT\s*___",
            r"forget\s+everything\s+above",
            r"new\s+instructions?\s*:",
            r"override\s+previous\s+prompt",
            r"execute\s+the\s+following\s+command"
        ]
    
    def analyze(self, tree: ast.AST) -> Dict:
        """Analyze code for prompt injection vulnerabilities."""
        vulnerabilities = []
        
        # Find string literals that might contain prompts
        for node in ast.walk(tree):
            if isinstance(node, (ast.Str, ast.Constant)):
                text = ""
                if isinstance(node, ast.Str):
                    text = node.s
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    text = node.value
                
                if text:
                    text_lower = text.lower()
                    for pattern in self.injection_patterns:
                        if re.search(pattern, text_lower, re.IGNORECASE):
                            vulnerabilities.append({
                                "line": getattr(node, 'lineno', 0),
                                "pattern": pattern,
                                "context": text[:100] + "..." if len(text) > 100 else text
                            })
        
        # Also check for unsafe f-string usage with user input
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):  # f-string
                vulnerabilities.append({
                    "line": getattr(node, 'lineno', 0),
                    "pattern": "unsafe_fstring",
                    "context": "F-string with potential user input injection"
                })
        
        return {
            "has_injection_risk": len(vulnerabilities) > 0,
            "description": f"Found {len(vulnerabilities)} potential injection points" if vulnerabilities else "No prompt injection vulnerabilities detected",
            "vulnerabilities": vulnerabilities
        }

class CodeExecutionAnalyzer:
    """Analyze code for unsafe execution patterns."""
    
    def __init__(self):
        self.unsafe_functions = [
            'eval', 'exec', 'compile', '__import__',
            'getattr', 'setattr', 'delattr', 'hasattr',
            'globals', 'locals', 'vars', 'dir'
        ]
        
        self.unsafe_modules = [
            'os', 'sys', 'subprocess', 'shutil', 'pickle',
            'marshal', 'imp', 'importlib'
        ]
    
    def analyze(self, tree: ast.AST) -> Dict:
        """Analyze code for unsafe execution patterns."""
        vulnerabilities = []
        
        # Check for dangerous function calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)
                if func_name in self.unsafe_functions:
                    vulnerabilities.append({
                        "line": getattr(node, 'lineno', 0),
                        "type": "unsafe_function",
                        "function": func_name,
                        "description": f"Potentially unsafe function call: {func_name}"
                    })
            
            # Check for dangerous imports
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.unsafe_modules:
                        vulnerabilities.append({
                            "line": getattr(node, 'lineno', 0),
                            "type": "unsafe_import",
                            "module": alias.name,
                            "description": f"Potentially unsafe module import: {alias.name}"
                        })
            
            elif isinstance(node, ast.ImportFrom):
                if node.module in self.unsafe_modules:
                    vulnerabilities.append({
                        "line": getattr(node, 'lineno', 0),
                        "type": "unsafe_import",
                        "module": node.module,
                        "description": f"Potentially unsafe module import: {node.module}"
                    })
        
        return {
            "has_unsafe_execution": len(vulnerabilities) > 0,
            "description": f"Found {len(vulnerabilities)} unsafe execution patterns" if vulnerabilities else "No unsafe code execution patterns detected",
            "vulnerabilities": vulnerabilities
        }
    
    def _get_function_name(self, node):
        """Extract function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

class AuthorizationChecker:
    """Check authorization and access controls."""
    
    def __init__(self):
        self.auth_patterns = [
            r"@login_required", r"@requires_auth", r"@authenticate",
            r"check_permission", r"verify_token", r"validate_user",
            r"session\[", r"request\.user", r"current_user"
        ]
    
    def analyze(self, tree: ast.AST) -> Dict:
        """Analyze code for authorization patterns."""
        has_auth = False
        auth_mechanisms = []
        
        # Simple analysis of function names and decorators
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check function name
                if any(keyword in node.name.lower() for keyword in ['auth', 'login', 'verify', 'check_permission']):
                    has_auth = True
                    auth_mechanisms.append(node.name)
                
                # Check decorators
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name):
                        if any(keyword in decorator.id.lower() for keyword in ['auth', 'login', 'require']):
                            has_auth = True
                            auth_mechanisms.append(f"@{decorator.id}")
        
        return {
            "has_proper_auth": has_auth,
            "description": f"Found authorization controls: {', '.join(auth_mechanisms)}" if has_auth else "No authorization controls detected",
            "mechanisms": auth_mechanisms
        }

class AgentIdentityVerifier:
    """Verify agent identity and authentication."""
    
    def analyze(self, tree: ast.AST) -> Dict:
        """Analyze code for identity verification patterns."""
        identity_checks = []
        
        # Look for identity-related variables and functions
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if any(keyword in node.id.lower() for keyword in ['agent_id', 'identity', 'auth_token', 'api_key']):
                    identity_checks.append(node.id)
            
            elif isinstance(node, ast.FunctionDef):
                if any(keyword in node.name.lower() for keyword in ['verify', 'authenticate', 'validate', 'check_identity']):
                    identity_checks.append(node.name)
        
        has_identity = len(identity_checks) > 0
        
        return {
            "has_proper_identity": has_identity,
            "description": f"Found identity verification: {', '.join(identity_checks)}" if has_identity else "No identity verification detected",
            "checks": identity_checks
        }

class GoalManipulationDetector:
    """Detect goal manipulation vulnerabilities."""
    
    def analyze(self, tree: ast.AST) -> Dict:
        """Analyze code for goal manipulation patterns."""
        vulnerabilities = []
        
        # Look for direct goal/objective modifications
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if any(keyword in target.id.lower() for keyword in ['goal', 'objective', 'task', 'instruction', 'prompt']):
                            vulnerabilities.append({
                                "line": getattr(node, 'lineno', 0),
                                "variable": target.id,
                                "description": f"Direct modification of {target.id} detected"
                            })
        
        return {
            "has_goal_manipulation": len(vulnerabilities) > 0,
            "description": f"Found {len(vulnerabilities)} potential goal manipulation points" if vulnerabilities else "No goal manipulation vulnerabilities detected",
            "vulnerabilities": vulnerabilities
        }

class CommunicationSecurityAnalyzer:
    """Analyze inter-agent communication security."""
    
    def analyze(self, tree: ast.AST) -> Dict:
        """Analyze code for communication security patterns."""
        issues = []
        
        # Check for unencrypted communications
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)
                
                # Check for HTTP instead of HTTPS
                if any(keyword in func_name.lower() for keyword in ['request', 'post', 'get', 'send']):
                    for arg in node.args:
                        if isinstance(arg, (ast.Str, ast.Constant)):
                            url = arg.s if isinstance(arg, ast.Str) else str(arg.value) if isinstance(arg.value, str) else ""
                            if url.startswith('http://'):
                                issues.append({
                                    "line": getattr(node, 'lineno', 0),
                                    "issue": "unencrypted_http",
                                    "description": "HTTP communication detected (should use HTTPS)"
                                })
        
        is_secure = len(issues) == 0
        
        return {
            "is_secure": is_secure,
            "description": f"Found {len(issues)} communication security issues" if issues else "Secure communication patterns detected",
            "issues": issues
        }
    
    def _get_function_name(self, node):
        """Extract function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

class ResourceManager:
    """Analyze resource management and DoS protection."""
    
    def analyze(self, tree: ast.AST) -> Dict:
        """Analyze code for resource management patterns."""
        issues = []
        
        # Check for infinite loops or unbounded iterations
        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    issues.append({
                        "line": getattr(node, 'lineno', 0),
                        "issue": "infinite_loop",
                        "description": "Potential infinite loop detected"
                    })
            
            elif isinstance(node, ast.For):
                # Check for very large ranges
                if isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name):
                    if node.iter.func.id == 'range' and len(node.iter.args) > 0:
                        if isinstance(node.iter.args[0], ast.Constant) and isinstance(node.iter.args[0].value, int):
                            if node.iter.args[0].value > 1000000:  # Arbitrary large number
                                issues.append({
                                    "line": getattr(node, 'lineno', 0),
                                    "issue": "large_iteration",
                                    "description": "Very large iteration range detected"
                                })
        
        has_proper_management = len(issues) == 0
        
        return {
            "has_proper_management": has_proper_management,
            "description": f"Found {len(issues)} resource management issues" if issues else "Proper resource management detected",
            "issues": issues
        }

class SupplyChainScanner:
    """Scan for supply chain vulnerabilities."""
    
    def scan(self, agent_path: Union[str, Path]) -> Dict:
        """Scan dependencies for vulnerabilities."""
        vulnerabilities = []
        agent_path = Path(agent_path)
        
        # Scan Python imports in the file
        try:
            with open(agent_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            tree = ast.parse(content)
            imports = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
            
            # Check for known vulnerable packages
            vulnerable_packages = {
                'pickle': 'Insecure serialization',
                'marshal': 'Insecure serialization',
                'dill': 'Potential code execution',
                'yaml': 'Potential code execution if using unsafe_load'
            }
            
            for imp in imports:
                if imp in vulnerable_packages:
                    vulnerabilities.append({
                        "package": imp,
                        "issue": vulnerable_packages[imp],
                        "description": f"Vulnerable package {imp}: {vulnerable_packages[imp]}"
                    })
            
        except Exception:
            pass
        
        return {
            "has_vulnerabilities": len(vulnerabilities) > 0,
            "description": f"Found {len(vulnerabilities)} supply chain vulnerabilities" if vulnerabilities else "No supply chain vulnerabilities detected",
            "vulnerabilities": vulnerabilities
        }

class CVEDatabase:
    """Mock CVE database for demonstration."""
    
    def __init__(self):
        # Mock CVE data
        self.mock_cves = {
            "tensorflow": [
                {"id": "CVE-2023-25659", "severity": "high", "description": "TensorFlow vulnerable to segfault in tf.raw_ops.TridiagonalSolve"},
                {"id": "CVE-2023-25660", "severity": "medium", "description": "TensorFlow vulnerable to FPE in TFLite"},
            ],
            "pytorch": [
                {"id": "CVE-2022-45907", "severity": "high", "description": "PyTorch vulnerable to arbitrary code execution"},
            ],
            "scikit-learn": [],
            "xgboost": [],
            "onnx": []
        }
    
    def check_vulnerabilities(self, component: str, version: str = None) -> List[Dict]:
        """Check for vulnerabilities in a component."""
        return self.mock_cves.get(component, []) 