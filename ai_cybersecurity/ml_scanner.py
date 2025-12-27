"""
ML Model Vulnerability Scanner Module
"""

import pickle
import joblib
from pathlib import Path
from typing import Dict, List, Optional, Union
import numpy as np
import ast
import re
import hashlib
import tempfile
import sys
from pydantic import BaseModel

from ai_cybersecurity.utils import VulnerabilityLevel, VulnerabilityReport
from ai_cybersecurity.integration import (
    FoolboxAdversarialTester,
    CleverHansAdversarialTester,
    ModelFrameworkDetector,
    CVEDatabase,
)

class MLScanner:
    """Scanner for ML model vulnerabilities."""
    
    def __init__(self):
        self.foolbox_tester = FoolboxAdversarialTester()
        self.cleverhans_tester = CleverHansAdversarialTester()
        self.framework_detector = ModelFrameworkDetector()
        self.cve_database = CVEDatabase()
        
        # Known malicious patterns in pickle files
        self.malicious_patterns = [
            b'os.system', b'subprocess.call', b'subprocess.run',
            b'eval', b'exec', b'__import__', b'compile',
            b'open', b'file', b'input', b'raw_input',
            b'getattr', b'setattr', b'delattr',
            b'globals', b'locals', b'vars',
            b'__builtins__', b'__globals__'
        ]
    
    def scan_model(self, model_path: Union[str, Path]) -> List[VulnerabilityReport]:
        """
        Scan an ML model for vulnerabilities.
        
        Args:
            model_path: Path to the model file
            
        Returns:
            List of vulnerability reports
        """
        model_path = Path(model_path)
        vulnerabilities = []
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        # Detect framework
        framework = self.framework_detector.detect(model_path)
        
        # Check serialization method
        if self._is_insecure_serialization(model_path):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.HIGH,
                    title="Insecure Serialization",
                    description=f"Model uses insecure serialization method ({model_path.suffix}). Pickle and joblib files can execute arbitrary code when loaded.",
                    remediation="Use secure serialization formats like ONNX, TensorFlow SavedModel, or HuggingFace safetensors",
                    affected_components=[str(model_path)],
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                        "https://docs.python.org/3/library/pickle.html#module-pickle"
                    ]
                )
            )
        
        # Check for malicious payloads
        malicious_results = self._contains_malicious_payload(model_path)
        if malicious_results["is_malicious"]:
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.CRITICAL,
                    title="Malicious Payload Detected",
                    description=f"Model contains potentially malicious code: {malicious_results['details']}",
                    remediation="Do not load this model. Verify model source and obtain from trusted sources only",
                    affected_components=[str(model_path)],
                    references=[
                        "https://huntr.dev/",
                        "https://github.com/advisories"
                    ]
                )
            )
        
        # Check file size (suspiciously large models might contain hidden data)
        file_size_mb = model_path.stat().st_size / (1024 * 1024)
        if file_size_mb > 1000:  # Models larger than 1GB
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.MEDIUM,
                    title="Unusually Large Model File",
                    description=f"Model file is {file_size_mb:.1f}MB, which is unusually large and may contain hidden data",
                    remediation="Verify model contents and ensure file size is appropriate for the model architecture",
                    affected_components=[str(model_path)]
                )
            )
        
        # Run adversarial tests (if framework is supported)
        if framework != framework.UNKNOWN:
            adv_vulnerabilities = self._run_adversarial_tests(model_path)
            vulnerabilities.extend(adv_vulnerabilities)
        
        # Check explainability
        if not self._has_explainability(model_path):
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.MEDIUM,
                    title="Missing Explainability",
                    description="Model lacks explainability tools, making it difficult to understand predictions and detect bias",
                    remediation="Implement SHAP, LIME, or other explainability methods to understand model decisions",
                    affected_components=[str(model_path)],
                    references=[
                        "https://github.com/slundberg/shap",
                        "https://github.com/marcotcr/lime"
                    ]
                )
            )
        
        # Check for CVEs related to the framework
        if framework != framework.UNKNOWN:
            cve_vulnerabilities = self._check_framework_cves(framework)
            vulnerabilities.extend(cve_vulnerabilities)
        
        # Check model metadata and provenance
        metadata_vulns = self._check_model_metadata(model_path)
        vulnerabilities.extend(metadata_vulns)
        
        return vulnerabilities
    
    def _is_insecure_serialization(self, model_path: Path) -> bool:
        """Check if model uses insecure serialization."""
        insecure_extensions = ['.pkl', '.pickle', '.joblib', '.dill']
        
        if model_path.suffix.lower() in insecure_extensions:
            return True
        
        # Check file contents for pickle magic bytes
        try:
            with open(model_path, 'rb') as f:
                header = f.read(10)
                # Pickle magic bytes
                if header.startswith(b'\x80\x03') or header.startswith(b'\x80\x04') or header.startswith(b'\x80\x05'):
                    return True
                # Check for pickle protocol 2
                if b'pickle' in header[:100] or b'cPickle' in header[:100]:
                    return True
        except Exception:
            pass
        
        return False
    
    def _contains_malicious_payload(self, model_path: Path) -> Dict:
        """Check for malicious payloads in model file."""
        try:
            with open(model_path, 'rb') as f:
                content = f.read()
            
            detected_patterns = []
            
            # Check for known malicious byte patterns
            for pattern in self.malicious_patterns:
                if pattern in content:
                    detected_patterns.append(pattern.decode('utf-8', errors='ignore'))
            
            # Check for suspicious imports in pickle files
            if model_path.suffix.lower() in ['.pkl', '.pickle']:
                suspicious_imports = self._analyze_pickle_imports(model_path)
                detected_patterns.extend(suspicious_imports)
            
            # Check for embedded scripts
            script_patterns = [
                b'import os', b'import sys', b'import subprocess',
                b'exec(', b'eval(', b'__import__(',
                b'open(', b'file(', b'input(',
                b'system(', b'shell=True'
            ]
            
            for pattern in script_patterns:
                if pattern in content:
                    detected_patterns.append(f"Embedded script: {pattern.decode('utf-8', errors='ignore')}")
            
            return {
                "is_malicious": len(detected_patterns) > 0,
                "details": "; ".join(detected_patterns) if detected_patterns else "Clean",
                "patterns": detected_patterns
            }
            
        except Exception as e:
            return {
                "is_malicious": True,  # Assume malicious if can't analyze
                "details": f"Failed to analyze file: {str(e)}",
                "patterns": []
            }
    
    def _analyze_pickle_imports(self, model_path: Path) -> List[str]:
        """Analyze imports in pickle file without executing it."""
        suspicious_imports = []
        
        try:
            # Use pickletools to disassemble without executing
            import pickletools
            import io
            
            with open(model_path, 'rb') as f:
                output = io.StringIO()
                pickletools.dis(f, output)
                disassembly = output.getvalue()
            
            # Look for suspicious global imports
            lines = disassembly.split('\n')
            for line in lines:
                if 'GLOBAL' in line:
                    # Extract the global name
                    parts = line.split()
                    if len(parts) > 1:
                        global_name = parts[-1]
                        if any(dangerous in global_name.lower() for dangerous in 
                               ['os.', 'sys.', 'subprocess.', 'eval', 'exec', '__import__']):
                            suspicious_imports.append(f"Suspicious global: {global_name}")
                            
        except Exception:
            # If pickletools fails, fall back to string analysis
            try:
                with open(model_path, 'rb') as f:
                    content = f.read()
                content_str = content.decode('latin1', errors='ignore')
                
                dangerous_modules = ['os', 'sys', 'subprocess', 'builtins', '__builtin__']
                for module in dangerous_modules:
                    if f'\n{module}\n' in content_str or f'\r{module}\r' in content_str:
                        suspicious_imports.append(f"Suspicious module reference: {module}")
                        
            except Exception:
                pass
        
        return suspicious_imports
    
    def _run_adversarial_tests(self, model_path: Path) -> List[VulnerabilityReport]:
        """Run adversarial robustness tests."""
        vulnerabilities = []
        
        try:
            # Run Foolbox tests
            foolbox_results = self.foolbox_tester.test_model(model_path)
            if foolbox_results.is_vulnerable:
                vulnerabilities.append(
                    VulnerabilityReport(
                        level=VulnerabilityLevel.HIGH,
                        title="Adversarial Vulnerability (Foolbox)",
                        description=f"Model vulnerable to {foolbox_results.attack_type} attacks with {foolbox_results.success_rate:.1%} success rate",
                        remediation="Implement adversarial training, input validation, or robust model architecture",
                        affected_components=[str(model_path)],
                        references=[
                            "https://github.com/bethgelab/foolbox",
                            "https://arxiv.org/abs/1412.6572"
                        ]
                    )
                )
            
            # Run CleverHans tests
            cleverhans_results = self.cleverhans_tester.test_model(model_path)
            if cleverhans_results.is_vulnerable:
                vulnerabilities.append(
                    VulnerabilityReport(
                        level=VulnerabilityLevel.HIGH,
                        title="Adversarial Vulnerability (CleverHans)",
                        description=f"Model vulnerable to {cleverhans_results.attack_type} attacks with {cleverhans_results.success_rate:.1%} success rate",
                        remediation="Implement adversarial training, gradient masking, or certified defenses",
                        affected_components=[str(model_path)],
                        references=[
                            "https://github.com/cleverhans-lab/cleverhans",
                            "https://arxiv.org/abs/1706.06083"
                        ]
                    )
                )
                
        except Exception as e:
            vulnerabilities.append(
                VulnerabilityReport(
                    level=VulnerabilityLevel.LOW,
                    title="Adversarial Testing Failed",
                    description=f"Could not perform adversarial testing: {str(e)}",
                    remediation="Manually verify model robustness against adversarial examples",
                    affected_components=[str(model_path)]
                )
            )
        
        return vulnerabilities
    
    def _has_explainability(self, model_path: Path) -> bool:
        """Check if model has explainability tools."""
        # Check for common explainability file patterns
        model_dir = model_path.parent
        explainability_files = [
            'shap_values.pkl', 'lime_explainer.pkl', 'explainer.pkl',
            'feature_importance.json', 'model_explanation.json'
        ]
        
        for exp_file in explainability_files:
            if (model_dir / exp_file).exists():
                return True
        
        # Check if it's a framework that typically includes explainability
        framework = self.framework_detector.detect(model_path)
        if framework == framework.SCIKIT_LEARN:
            # Scikit-learn models often have built-in feature importance
            try:
                model = joblib.load(model_path)
                if hasattr(model, 'feature_importances_') or hasattr(model, 'coef_'):
                    return True
            except Exception:
                pass
        
        return False
    
    def _check_framework_cves(self, framework: 'ModelFramework') -> List[VulnerabilityReport]:
        """Check for known CVEs in the ML framework."""
        vulnerabilities = []
        
        framework_mapping = {
            framework.TENSORFLOW: "tensorflow",
            framework.PYTORCH: "pytorch", 
            framework.SCIKIT_LEARN: "scikit-learn",
            framework.XGBOOST: "xgboost",
            framework.ONNX: "onnx"
        }
        
        if framework in framework_mapping:
            component_name = framework_mapping[framework]
            try:
                cves = self.cve_database.check_vulnerabilities(component_name)
                
                for cve in cves[:3]:  # Limit to top 3 most relevant
                    severity_mapping = {
                        'critical': VulnerabilityLevel.CRITICAL,
                        'high': VulnerabilityLevel.HIGH,
                        'medium': VulnerabilityLevel.MEDIUM,
                        'low': VulnerabilityLevel.LOW
                    }
                    
                    severity = severity_mapping.get(cve['severity'], VulnerabilityLevel.MEDIUM)
                    
                    vulnerabilities.append(
                        VulnerabilityReport(
                            level=severity,
                            title=f"Known CVE in {component_name}",
                            description=cve['description'][:200] + "..." if len(cve['description']) > 200 else cve['description'],
                            remediation=f"Update {component_name} to the latest version and review security advisories",
                            cve_id=cve['id'],
                            affected_components=[component_name],
                            references=[f"https://nvd.nist.gov/vuln/detail/{cve['id']}"]
                        )
                    )
                    
            except Exception:
                pass  # CVE lookup failed, continue without it
        
        return vulnerabilities
    
    def _check_model_metadata(self, model_path: Path) -> List[VulnerabilityReport]:
        """Check model metadata for security issues."""
        vulnerabilities = []
        
        try:
            # Check file permissions
            import stat
            file_stat = model_path.stat()
            
            # Check if file is world-writable (security risk)
            if file_stat.st_mode & stat.S_IWOTH:
                vulnerabilities.append(
                    VulnerabilityReport(
                        level=VulnerabilityLevel.MEDIUM,
                        title="Insecure File Permissions",
                        description="Model file is world-writable, allowing unauthorized modifications",
                        remediation="Change file permissions to restrict write access",
                        affected_components=[str(model_path)]
                    )
                )
            
            # Check file hash for integrity
            file_hash = self._calculate_file_hash(model_path)
            
            # Look for model metadata files
            metadata_files = [
                model_path.with_suffix('.json'),
                model_path.with_suffix('.yaml'),
                model_path.with_suffix('.yml'),
                model_path.parent / 'model_info.json',
                model_path.parent / 'metadata.json'
            ]
            
            metadata_found = False
            for meta_file in metadata_files:
                if meta_file.exists():
                    metadata_found = True
                    break
            
            if not metadata_found:
                vulnerabilities.append(
                    VulnerabilityReport(
                        level=VulnerabilityLevel.LOW,
                        title="Missing Model Metadata",
                        description="No metadata file found for model provenance and version tracking",
                        remediation="Create metadata file with model version, training data, and provenance information",
                        affected_components=[str(model_path)]
                    )
                )
                
        except Exception:
            pass
        
        return vulnerabilities
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "" 