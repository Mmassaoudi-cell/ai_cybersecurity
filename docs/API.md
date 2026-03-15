# API Reference

Complete programmatic API reference for the **AI Cybersecurity Platform** — a unified platform for automated cybersecurity vulnerability assessment in Machine Learning models and AI agents.

**Version:** 1.0.0  
**Authors:** Mohamed Massaoudi, Katherine R. Davis  
**License:** MIT

---

## Table of Contents

- [Package Overview](#package-overview)
- [Core Classes](#core-classes)
  - [MLScanner](#mlscanner)
  - [AgentScanner](#agentscanner)
  - [ModelImmunizer](#modelimmunizer)
  - [Reporter](#reporter)
- [Data Models](#data-models)
  - [VulnerabilityReport](#vulnerabilityreport)
  - [ScanResult](#scanresult)
  - [VulnerabilityLevel](#vulnerabilitylevel)
  - [ModelFramework](#modelframework)
  - [AgentFramework](#agentframework)
  - [AdversarialTestResult](#adversarialtestresult)
- [Immunization Wrappers](#immunization-wrappers)
  - [AdversarialProtectedModel](#adversarialprotectedmodel)
  - [SecureSerializationWrapper](#secureserializationwrapper)
  - [InputValidationWrapper](#inputvalidationwrapper)
  - [DifferentialPrivacyWrapper](#differentialprivacywrapper)
  - [ExplainableModelWrapper](#explainablemodelwrapper)
  - [MetadataProtectedWrapper](#metadataprotectedwrapper)
- [Integration Components](#integration-components)
  - [FoolboxAdversarialTester](#foolboxadversarialtester)
  - [CleverHansAdversarialTester](#cleverhansadversarialtester)
  - [ModelFrameworkDetector](#modelframeworkdetector)
  - [PromptInjectionDetector](#promptinjectiondetector)
  - [CodeExecutionAnalyzer](#codeexecutionanalyzer)
  - [AuthorizationChecker](#authorizationchecker)
  - [AgentIdentityVerifier](#agentidentityverifier)
  - [GoalManipulationDetector](#goalmanipulationdetector)
  - [CommunicationSecurityAnalyzer](#communicationsecurityanalyzer)
  - [ResourceManager](#resourcemanager)
  - [SupplyChainScanner](#supplychainscanner)
  - [CVEDatabase](#cvedatabase)
- [Utility Functions](#utility-functions)
- [CLI Reference](#cli-reference)
- [GUI Application](#gui-application)
- [Quick-Start Examples](#quick-start-examples)

---

## Package Overview

The `ai_cybersecurity` package exposes the following public symbols via `__init__.py`:

```python
from ai_cybersecurity import (
    MLScanner,            # ML model vulnerability scanner
    AgentScanner,         # AI agent vulnerability scanner
    Reporter,             # Multi-format report generator
    VulnerabilityLevel,   # Severity level enumeration
    VulnerabilityReport,  # Pydantic data model for findings
    ModelImmunizer,       # Automated model immunization
    cli_app,              # Typer CLI application instance
)
```

**Minimum Python version:** 3.8+

---

## Core Classes

### MLScanner

**Module:** `ai_cybersecurity.ml_scanner`

Performs comprehensive cybersecurity vulnerability scanning of serialized ML model files.

#### Constructor

```python
scanner = MLScanner()
```

No arguments are required. The constructor initialises the following internal components automatically:

| Component | Type | Purpose |
|-----------|------|---------|
| `foolbox_tester` | `FoolboxAdversarialTester` | FGSM adversarial robustness testing |
| `cleverhans_tester` | `CleverHansAdversarialTester` | Carlini & Wagner adversarial testing |
| `framework_detector` | `ModelFrameworkDetector` | Automatic framework identification |
| `cve_database` | `CVEDatabase` | Known CVE lookup for detected framework |

#### Methods

##### `scan_model(model_path) → List[VulnerabilityReport]`

Scan an ML model file for cybersecurity vulnerabilities.

| Parameter | Type | Description |
|-----------|------|-------------|
| `model_path` | `str` or `pathlib.Path` | Path to the model file to scan |

**Returns:** A list of `VulnerabilityReport` objects.

**Raises:** `FileNotFoundError` if the model file does not exist.

**Checks performed (in order):**

1. **Framework detection** — identifies TensorFlow, PyTorch, scikit-learn, XGBoost, ONNX, or unknown.
2. **Insecure serialization** — flags `.pkl`, `.pickle`, `.joblib`, `.dill` extensions and pickle magic bytes.
3. **Malicious payload scanning** — detects `os.system`, `subprocess`, `eval`, `exec`, `__import__`, and other dangerous byte patterns. For pickle files, also disassembles opcodes with `pickletools` to find suspicious `GLOBAL` imports without executing the file.
4. **Unusual file size** — flags models larger than 1 GB.
5. **Adversarial robustness testing** — runs Foolbox (FGSM) and CleverHans (Carlini & Wagner) tests if the framework is recognised.
6. **Explainability gap detection** — checks for companion SHAP/LIME files or built-in `feature_importances_`/`coef_` attributes.
7. **Framework CVE lookup** — queries known CVEs for the detected framework version.
8. **Model metadata & provenance** — checks file permissions (world-writable) and presence of metadata files (`.json`, `.yaml`, `model_info.json`).

**Example:**

```python
from ai_cybersecurity import MLScanner

scanner = MLScanner()
vulnerabilities = scanner.scan_model("models/classifier.pkl")

for vuln in vulnerabilities:
    print(f"[{vuln.level.value.upper()}] {vuln.title}")
    print(f"  {vuln.description}")
    print(f"  Remediation: {vuln.remediation}")
```

---

### AgentScanner

**Module:** `ai_cybersecurity.agent_scanner`

Performs AST-based static analysis of AI agent Python source files.

#### Constructor

```python
scanner = AgentScanner()
```

Initialises the following internal analysers:

| Component | Type | Purpose |
|-----------|------|---------|
| `prompt_detector` | `PromptInjectionDetector` | Prompt injection vulnerability detection |
| `code_analyzer` | `CodeExecutionAnalyzer` | Unsafe `eval`/`exec` detection |
| `auth_checker` | `AuthorizationChecker` | Access control assessment |
| `identity_verifier` | `AgentIdentityVerifier` | Agent authentication checks |
| `goal_detector` | `GoalManipulationDetector` | Goal/objective tampering detection |
| `comm_analyzer` | `CommunicationSecurityAnalyzer` | Inter-agent communication security |
| `resource_manager` | `ResourceManager` | DoS / resource exhaustion checks |
| `supply_chain_scanner` | `SupplyChainScanner` | Dependency vulnerability scanning |

#### Methods

##### `scan_agent(agent_path) → List[VulnerabilityReport]`

Scan an AI agent Python file for cybersecurity vulnerabilities.

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_path` | `str` or `pathlib.Path` | Path to the `.py` agent source file |

**Returns:** A list of `VulnerabilityReport` objects.

**Raises:** `FileNotFoundError` if the agent file does not exist.

**Checks performed (in order):**

1. **AST parsing** — parses the source; reports `HIGH` if syntax errors prevent analysis.
2. **Prompt injection** — regex-based pattern matching for known injection strings (e.g., "ignore previous instructions", ChatML tokens, jailbreak prompts) and unsafe f-string usage.
3. **Unsafe code execution** — flags calls to `eval`, `exec`, `compile`, `__import__`, `getattr`, `setattr`, and imports of `os`, `subprocess`, `pickle`, `marshal`.
4. **Authorization controls** — looks for authentication decorators (`@login_required`, `@requires_auth`) and auth-related function names.
5. **Agent identity** — detects identity verification patterns (`agent_id`, `auth_token`, `verify`, `authenticate`).
6. **Goal manipulation** — finds direct assignments to variables named `goal`, `objective`, `task`, `instruction`, `prompt`.
7. **Communication security** — flags HTTP (non-HTTPS) URLs in network calls.
8. **Resource management** — detects infinite loops (`while True`) and very large iteration ranges (> 1 000 000).
9. **Supply chain** — identifies imports of known-vulnerable packages (`pickle`, `marshal`, `dill`, `yaml`).

**Example:**

```python
from ai_cybersecurity import AgentScanner

scanner = AgentScanner()
vulnerabilities = scanner.scan_agent("agents/chatbot.py")

for vuln in vulnerabilities:
    print(f"[{vuln.level.value.upper()}] {vuln.title}: {vuln.description}")
```

---

### ModelImmunizer

**Module:** `ai_cybersecurity.immunization`

Provides automated remediation by wrapping a scanned model with one or more protection layers.

#### Constructor

```python
immunizer = ModelImmunizer()
```

Initialises a `ModelFrameworkDetector` and registers the following protection methods:

| Key | Method | Wrapper Produced |
|-----|--------|-----------------|
| `adversarial_training` | `_apply_adversarial_training` | `AdversarialProtectedModel` |
| `secure_serialization` | `_apply_secure_serialization` | `SecureSerializationWrapper` |
| `input_validation` | `_apply_input_validation` | `InputValidationWrapper` |
| `differential_privacy` | `_apply_differential_privacy` | `DifferentialPrivacyWrapper` |
| `model_encryption` | `_apply_model_encryption` | `SecureSerializationWrapper` (with encryption) |
| `explainability` | `_add_explainability_layer` | `ExplainableModelWrapper` |
| `metadata_protection` | `_protect_metadata` | `MetadataProtectedWrapper` |

#### Methods

##### `immunize_model(model_path, vulnerabilities, protection_level) → Dict`

Immunize an ML model against a list of detected vulnerabilities.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `model_path` | `str` or `Path` | — | Path to the original model file |
| `vulnerabilities` | `List[VulnerabilityReport]` | — | Vulnerabilities to remediate |
| `protection_level` | `str` | `"standard"` | `"basic"`, `"standard"`, or `"maximum"` |

**Returns:** A dictionary with the following keys:

```python
{
    "original_path": str,        # Path to the original model
    "immunized_path": str,       # Path to the saved immunized model
    "protection_results": dict,  # Per-vulnerability protection outcome
    "report": {                  # Immunization summary
        "timestamp": str,
        "original_model": str,
        "immunized_model": str,
        "total_vulnerabilities": int,
        "successful_protections": int,
        "protection_rate": float,          # 0.0–1.0
        "vulnerabilities_addressed": list,
        "protection_methods_applied": list,
        "failed_protections": list,
        "recommendations": list,
    },
    "status": "success" | "failed"
}
```

**Protection-level effects:**

| Level | Adversarial ε | Anomaly Threshold | Encryption | Privacy ε |
|-------|--------------|-------------------|------------|-----------|
| `basic` | 0.05 | 2.0 | None | 2.0 |
| `standard` | 0.10 | 3.0 | Obfuscation | 1.0 |
| `maximum` | 0.15 | 4.0 | AES-256 + PBKDF2 | 0.5 |

**Supported model formats for immunization:** `.pkl`, `.pickle`, `.joblib`.

**Example:**

```python
from ai_cybersecurity import MLScanner, ModelImmunizer

scanner = MLScanner()
vulnerabilities = scanner.scan_model("models/classifier.pkl")

immunizer = ModelImmunizer()
result = immunizer.immunize_model(
    "models/classifier.pkl",
    vulnerabilities,
    protection_level="standard"
)

print(f"Status: {result['status']}")
print(f"Immunized model saved to: {result['immunized_path']}")
print(f"Protection rate: {result['report']['protection_rate']:.0%}")
```

---

### Reporter

**Module:** `ai_cybersecurity.reporting`

Generates vulnerability scan reports in multiple formats.

#### Constructor

```python
reporter = Reporter()
```

Initialises a Rich console and a Jinja2 template environment rooted at `./templates`.

#### Methods

##### `generate_report(scan_result, format, output_path) → str`

Generate a formatted vulnerability report.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_result` | `ScanResult` | — | Result of a completed scan |
| `format` | `str` | `"json"` | Output format: `"json"`, `"html"`, or `"text"` |
| `output_path` | `str` or `Path` or `None` | `None` | Optional path to save the report to disk |

**Returns:** The report content as a string.

**Example:**

```python
from ai_cybersecurity import MLScanner, Reporter
from ai_cybersecurity.utils import ScanResult

scanner = MLScanner()
vulns = scanner.scan_model("models/classifier.pkl")

scan_result = ScanResult(
    vulnerabilities=vulns,
    target_path="models/classifier.pkl",
    scan_duration=2.5
)

reporter = Reporter()

# JSON report
json_report = reporter.generate_report(scan_result, format="json", output_path="report.json")

# HTML report (requires templates/report.html)
html_report = reporter.generate_report(scan_result, format="html", output_path="report.html")

# Text report (Rich-formatted)
text_report = reporter.generate_report(scan_result, format="text")
print(text_report)
```

---

## Data Models

All data models use [Pydantic v2](https://docs.pydantic.dev/) for validation and serialization.

### VulnerabilityReport

**Module:** `ai_cybersecurity.utils`

Structured representation of a single detected vulnerability.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | `VulnerabilityLevel` | *required* | Severity level |
| `title` | `str` | *required* | Short vulnerability title |
| `description` | `str` | *required* | Detailed description |
| `remediation` | `str` | *required* | Recommended remediation steps |
| `timestamp` | `datetime` | `datetime.now()` | Detection timestamp |
| `affected_components` | `List[str]` | `[]` | List of affected components |
| `cve_id` | `Optional[str]` | `None` | CVE identifier, if applicable |
| `references` | `List[str]` | `[]` | Reference URLs |
| `confidence` | `float` | `1.0` | Confidence score (0.0–1.0) |
| `impact_score` | `float` | `0.0` | Estimated impact score |
| `exploitability_score` | `float` | `0.0` | Estimated exploitability score |

**Methods:**

- `to_dict() → Dict[str, Any]` — Serialize the report to a plain dictionary.

### ScanResult

**Module:** `ai_cybersecurity.utils`

Container for a complete scan session.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vulnerabilities` | `List[VulnerabilityReport]` | *required* | Detected vulnerabilities |
| `target_path` | `str` | *required* | Path of the scanned target |
| `scan_duration` | `float` | *required* | Scan duration in seconds |
| `scan_timestamp` | `datetime` | `datetime.now()` | When the scan was performed |
| `scanner_version` | `str` | `"1.0.0"` | Scanner version |
| `risk_score` | `float` | computed | Overall risk score (0.0–4.0) |
| `total_vulnerabilities` | `int` | computed | Total vulnerability count |

**Methods:**

- `get_vulnerabilities_by_level(level: VulnerabilityLevel) → List[VulnerabilityReport]` — Filter by severity.
- `get_high_risk_vulnerabilities() → List[VulnerabilityReport]` — Get HIGH and CRITICAL findings.
- `to_summary_dict() → Dict[str, Any]` — Serialize to a summary dictionary.

### VulnerabilityLevel

**Module:** `ai_cybersecurity.utils`

```python
class VulnerabilityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

### ModelFramework

**Module:** `ai_cybersecurity.utils`

```python
class ModelFramework(Enum):
    TENSORFLOW = "tensorflow"
    PYTORCH = "pytorch"
    SCIKIT_LEARN = "scikit-learn"
    XGBOOST = "xgboost"
    ONNX = "onnx"
    HUGGINGFACE = "huggingface"
    UNKNOWN = "unknown"
```

### AgentFramework

**Module:** `ai_cybersecurity.utils`

```python
class AgentFramework(Enum):
    LANGCHAIN = "langchain"
    LLAMAINDEX = "llamaindex"
    AUTOGEN = "autogen"
    CREWAI = "crewai"
    CUSTOM = "custom"
    UNKNOWN = "unknown"
```

### AdversarialTestResult

**Module:** `ai_cybersecurity.integration`

```python
class AdversarialTestResult(BaseModel):
    is_vulnerable: bool       # Whether the model is vulnerable
    attack_type: str          # Attack method name (e.g. "FGSM", "CarliniWagner")
    success_rate: float       # Fraction of successful adversarial examples
    perturbation_size: float  # Norm of the perturbation applied
```

---

## Immunization Wrappers

All wrappers preserve the original model's `predict()` and `predict_proba()` interface so they can be used as drop-in replacements.

### AdversarialProtectedModel

Wraps a model with adversarial input defence. Uses `AdvancedAdversarialTraining` for FGSM, PGD, C&W, and DeepFool example generation, and `AdvancedInputValidation` for anomaly/threat detection.

```python
protected = AdversarialProtectedModel(original_model, protection_level="standard")
predictions = protected.predict(X)
```

### SecureSerializationWrapper

Adds integrity checking (SHA-256, HMAC, timestamps), model obfuscation, and optional AES-256 encryption (at `"maximum"` level using `cryptography.fernet`).

```python
wrapped = SecureSerializationWrapper(original_model, protection_level="standard")
assert wrapped.verify_integrity()
predictions = wrapped.predict(X)
```

### InputValidationWrapper

Provides multi-layer input validation: type/shape checks, NaN/Inf cleaning, anomaly detection (Z-score), threat-pattern detection (adversarial, injection, evasion), and statistical normalisation.

```python
wrapped = InputValidationWrapper(original_model, protection_level="standard")
predictions = wrapped.predict(X)  # input is validated before forwarding
```

### DifferentialPrivacyWrapper

Adds calibrated noise to model predictions using Laplace, Gaussian, or Exponential mechanisms. Manages a finite privacy budget.

```python
wrapped = DifferentialPrivacyWrapper(original_model, protection_level="standard")
predictions = wrapped.predict(X)

print(wrapped.get_privacy_stats())
# {'predictions_made': 1, 'max_predictions': 1000, 'privacy_budget_remaining': ..., ...}
```

### ExplainableModelWrapper

Logs predictions and tracks feature importance based on input magnitudes.

```python
wrapped = ExplainableModelWrapper(original_model)
predictions = wrapped.predict(X)
explanation = wrapped.explain_prediction(X)
print(explanation)
# {'feature_importance': [...], 'explanation': 'Feature importance based on input magnitude'}
```

### MetadataProtectedWrapper

Attaches creation-time metadata and an integrity hash to the model.

```python
wrapped = MetadataProtectedWrapper(original_model, protection_level="standard")
print(wrapped.get_metadata())
# {'creation_time': '...', 'protection_level': 'standard', 'integrity_hash': '...', 'version': '1.0'}
```

---

## Integration Components

**Module:** `ai_cybersecurity.integration`

These classes bridge the platform to external tools and analysis techniques.

### FoolboxAdversarialTester

Tests model adversarial robustness using [Foolbox](https://github.com/bethgelab/foolbox) FGSM attacks.

```python
tester = FoolboxAdversarialTester()
result: AdversarialTestResult = tester.test_model("model.pkl")
print(result.is_vulnerable, result.success_rate)
```

### CleverHansAdversarialTester

Tests model adversarial robustness using [CleverHans](https://github.com/cleverhans-lab/cleverhans) Carlini & Wagner attacks.

```python
tester = CleverHansAdversarialTester()
result: AdversarialTestResult = tester.test_model("model.h5")
```

### ModelFrameworkDetector

Detects the ML framework of a model file by extension and by inspecting file contents.

```python
detector = ModelFrameworkDetector()
framework: ModelFramework = detector.detect("model.pth")
# ModelFramework.PYTORCH
```

**Detection rules:**

| Extension | Framework |
|-----------|-----------|
| `.pkl` | Inspects pickle content for sklearn/torch/tf signatures |
| `.h5`, `.hdf5` | TensorFlow |
| `.onnx` | ONNX |
| `.pth`, `.pt` | PyTorch |
| `.joblib` | scikit-learn |

### PromptInjectionDetector

AST-based detector for prompt injection patterns. Scans string literals and f-strings in agent code against a configurable set of regex patterns (e.g., "ignore previous instructions", ChatML tokens, jailbreak phrases).

```python
import ast

detector = PromptInjectionDetector()
tree = ast.parse(open("agent.py").read())
result = detector.analyze(tree)
# {'has_injection_risk': True/False, 'description': '...', 'vulnerabilities': [...]}
```

### CodeExecutionAnalyzer

Detects unsafe function calls (`eval`, `exec`, `compile`, `__import__`, `getattr`, etc.) and imports of dangerous modules (`os`, `subprocess`, `pickle`, `marshal`).

```python
analyzer = CodeExecutionAnalyzer()
result = analyzer.analyze(tree)
# {'has_unsafe_execution': True/False, 'description': '...', 'vulnerabilities': [...]}
```

### AuthorizationChecker

Examines function names and decorators for authentication/authorization patterns.

```python
checker = AuthorizationChecker()
result = checker.analyze(tree)
# {'has_proper_auth': True/False, 'description': '...', 'mechanisms': [...]}
```

### AgentIdentityVerifier

Looks for identity-related variables (`agent_id`, `auth_token`, `api_key`) and verification functions.

```python
verifier = AgentIdentityVerifier()
result = verifier.analyze(tree)
# {'has_proper_identity': True/False, 'description': '...', 'checks': [...]}
```

### GoalManipulationDetector

Detects direct assignments to goal/objective/task/instruction/prompt variables.

```python
detector = GoalManipulationDetector()
result = detector.analyze(tree)
# {'has_goal_manipulation': True/False, 'description': '...', 'vulnerabilities': [...]}
```

### CommunicationSecurityAnalyzer

Flags HTTP (non-HTTPS) URLs in network-related function calls.

```python
analyzer = CommunicationSecurityAnalyzer()
result = analyzer.analyze(tree)
# {'is_secure': True/False, 'description': '...', 'issues': [...]}
```

### ResourceManager

Detects potential denial-of-service conditions: infinite loops (`while True`) and extremely large iteration ranges.

```python
manager = ResourceManager()
result = manager.analyze(tree)
# {'has_proper_management': True/False, 'description': '...', 'issues': [...]}
```

### SupplyChainScanner

Scans Python imports in agent files for known-vulnerable packages (`pickle`, `marshal`, `dill`, `yaml`).

```python
scanner = SupplyChainScanner()
result = scanner.scan("agent.py")
# {'has_vulnerabilities': True/False, 'description': '...', 'vulnerabilities': [...]}
```

### CVEDatabase

Looks up known CVEs for supported ML frameworks (TensorFlow, PyTorch, scikit-learn, XGBoost, ONNX).

```python
db = CVEDatabase()
cves = db.check_vulnerabilities("tensorflow")
# [{'id': 'CVE-2023-25659', 'severity': 'high', 'description': '...'}, ...]
```

---

## Utility Functions

**Module:** `ai_cybersecurity.utils`

| Function | Signature | Description |
|----------|-----------|-------------|
| `calculate_risk_score` | `(vulnerabilities: List[VulnerabilityReport]) → float` | Compute overall risk score (0.0–4.0) using severity weights and confidence. Applies diminishing returns for > 10 findings. |
| `categorize_vulnerability` | `(vuln: VulnerabilityReport) → str` | Categorize into `serialization`, `injection`, `authentication`, `communication`, `supply_chain`, `malware`, `adversarial`, `privacy`, `availability`, `explainability`, or `other`. |
| `format_file_size` | `(size_bytes: int) → str` | Human-readable file size (e.g., `"4.2 MB"`). |
| `format_timestamp` | `(timestamp: datetime) → str` | Format as `"YYYY-MM-DD HH:MM:SS"`. |
| `validate_file_path` | `(file_path: str) → Path` | Validate and return a `Path` object. Raises `FileNotFoundError` or `ValueError`. |
| `get_file_hash` | `(file_path: Path, algorithm: str = "sha256") → str` | Calculate file hash. Supports `md5`, `sha1`, `sha256`, `sha512`. |
| `extract_imports_from_code` | `(code: str) → List[str]` | Extract all imported module names from Python source code via AST. |
| `is_binary_file` | `(file_path: Path) → bool` | Check whether a file is binary (contains null bytes or non-UTF-8). |
| `sanitize_filename` | `(filename: str) → str` | Remove dangerous characters from a filename. |
| `create_vulnerability_summary` | `(vulnerabilities: List[VulnerabilityReport]) → Dict` | Generate a summary dict with totals by severity, by category, risk score, and most critical finding. |

---

## CLI Reference

**Module:** `ai_cybersecurity.cli`  
**Framework:** [Typer](https://typer.tiangolo.com/) with [Rich](https://rich.readthedocs.io/) formatting

The CLI is invoked via `python -m ai_cybersecurity.cli` or through the standalone executable `AI_Cybersecurity_CLI_Fixed.exe`.

### Commands

#### `scan-model`

Scan an ML model for cybersecurity vulnerabilities.

```
ai-cybersecurity scan-model <MODEL_PATH> [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--format` | `-f` | `table` | Output format: `table`, `json`, `html` |
| `--output` | `-o` | — | Save report to file |
| `--verbose` | `-v` | `False` | Show remediation and references columns |

**Example:**

```bash
python -m ai_cybersecurity.cli scan-model models/classifier.pkl --format json --output report.json
```

#### `scan-agent`

Scan an AI agent Python file for cybersecurity vulnerabilities.

```
ai-cybersecurity scan-agent <AGENT_PATH> [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--format` | `-f` | `table` | Output format: `table`, `json`, `html` |
| `--output` | `-o` | — | Save report to file |
| `--verbose` | `-v` | `False` | Show remediation and references columns |

**Example:**

```bash
python -m ai_cybersecurity.cli scan-agent agents/chatbot.py --verbose
```

#### `immunize`

Immunize an ML model against detected vulnerabilities.

```
ai-cybersecurity immunize <MODEL_PATH> [OPTIONS]
```

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--level` | `-l` | `standard` | Protection level: `basic`, `standard`, `maximum` |
| `--output-dir` | `-d` | — | Output directory for immunized model |
| `--force` | `-f` | `False` | Skip confirmation prompt |
| `--verbose` | `-v` | `False` | Show detailed recommendations |

**Supported formats:** `.pkl`, `.pickle`, `.joblib`

**Example:**

```bash
python -m ai_cybersecurity.cli immunize models/classifier.pkl --level maximum --force
```

#### `info`

Display platform information, supported formats, scan capabilities, and immunization features.

```bash
python -m ai_cybersecurity.cli info
```

---

## GUI Application

**Module:** `main.py`  
**Class:** `AISecurityGUI`  
**Framework:** tkinter / ttk (with optional Pillow for logo display)

Launch the graphical interface:

```bash
# From source
python main.py

# Or use the pre-built executable (Windows)
AI_Cybersecurity_Platform_Fixed.exe
```

### GUI Features

| Feature | Description |
|---------|-------------|
| **File Browser** | Browse and select ML model or AI agent files with format filtering |
| **Auto-detect / Manual Scan Type** | Automatically choose scanner based on extension, or force ML/Agent mode |
| **Threaded Scanning** | Non-blocking scan with progress indicator |
| **Results Table** | Treeview with severity-colour-coded rows |
| **Severity Summary** | Real-time counts of Critical, High, Medium, and Low findings |
| **Model Immunization Dialog** | Choose protection level (Basic/Standard/Maximum), review protections, start immunization |
| **Report Generation** | Export results as HTML, JSON, or plain text |
| **Keyboard Shortcuts** | `Ctrl+O` Open, `F5` Scan, `Ctrl+I` Immunize, `Ctrl+R` Report, `Ctrl+Q` Quit |
| **Help & About** | Built-in help guide, contact information, and platform version info |

### Standalone Executables

The `dist/` directory ships three pre-built Windows executables:

| Executable | Description |
|------------|-------------|
| `AI_Cybersecurity_Platform_Fixed.exe` | Full GUI application |
| `AI_Cybersecurity_Platform.exe` | GUI application (earlier build) |
| `AI_Cybersecurity_CLI_Fixed.exe` | CLI-only application |

These are self-contained (built with PyInstaller) and require no Python installation.

---

## Quick-Start Examples

### End-to-End: Scan → Immunize → Report

```python
from ai_cybersecurity import MLScanner, ModelImmunizer, Reporter
from ai_cybersecurity.utils import ScanResult
import time

# 1. Scan
scanner = MLScanner()
start = time.time()
vulns = scanner.scan_model("models/classifier.pkl")
duration = time.time() - start

print(f"Found {len(vulns)} vulnerabilities in {duration:.1f}s")

# 2. Immunize
if vulns:
    immunizer = ModelImmunizer()
    result = immunizer.immunize_model(
        "models/classifier.pkl",
        vulns,
        protection_level="standard"
    )
    print(f"Immunized model saved to: {result['immunized_path']}")
    print(f"Protection rate: {result['report']['protection_rate']:.0%}")

# 3. Report
scan_result = ScanResult(
    vulnerabilities=vulns,
    target_path="models/classifier.pkl",
    scan_duration=duration
)

reporter = Reporter()
reporter.generate_report(scan_result, format="html", output_path="security_report.html")
reporter.generate_report(scan_result, format="json", output_path="security_report.json")
```

### CI/CD Integration

```bash
# In a CI pipeline step
python -m ai_cybersecurity.cli scan-model models/production_model.pkl \
    --format json \
    --output scan_results.json

# Parse the JSON output to enforce quality gates
python -c "
import json, sys
with open('scan_results.json') as f:
    data = json.load(f)
criticals = [v for v in data['vulnerabilities'] if v['level'] == 'critical']
if criticals:
    print(f'FAILED: {len(criticals)} critical vulnerabilities found')
    sys.exit(1)
print('PASSED: No critical vulnerabilities')
"
```

### Plugin / Extension Pattern

```python
from ai_cybersecurity import MLScanner
from ai_cybersecurity.utils import VulnerabilityReport, VulnerabilityLevel

class CustomScanner:
    """Example custom scanner extending the platform."""

    def __init__(self):
        self.base_scanner = MLScanner()

    def scan_with_policy(self, model_path, max_file_size_mb=500):
        """Scan with organisation-specific policies."""
        from pathlib import Path

        vulns = self.base_scanner.scan_model(model_path)

        # Add custom policy check
        file_size = Path(model_path).stat().st_size / (1024 * 1024)
        if file_size > max_file_size_mb:
            vulns.append(VulnerabilityReport(
                level=VulnerabilityLevel.MEDIUM,
                title="Organisation Policy Violation",
                description=f"Model exceeds {max_file_size_mb} MB size limit ({file_size:.1f} MB)",
                remediation="Compress or prune the model to meet deployment size limits"
            ))

        return vulns
```

---

## Dependencies

### Required

| Package | Version | Purpose |
|---------|---------|---------|
| `pydantic` | ≥ 2.0.0 | Data validation and models |
| `typer[all]` | ≥ 0.9.0 | CLI framework |
| `rich` | ≥ 13.0.0 | Terminal formatting |
| `numpy` | ≥ 1.20.0 | Numerical computation |
| `pandas` | ≥ 1.3.0 | Data analysis |
| `scikit-learn` | ≥ 1.0.0 | ML utilities |
| `cryptography` | ≥ 38.0.0 | AES encryption, key derivation |
| `Pillow` | ≥ 9.0.0 | Image processing (GUI logo) |
| `requests` | ≥ 2.28.0 | HTTP requests |
| `scipy` | ≥ 1.7.0 | Signal filtering |
| `joblib` | ≥ 1.1.0 | Model serialization |
| `jinja2` | — | HTML report templating |

### Optional (for full ML support)

| Package | Version | Purpose |
|---------|---------|---------|
| `torch` | ≥ 1.10.0 | PyTorch model support |
| `tensorflow` | ≥ 2.8.0 | TensorFlow model support |
| `foolbox` | ≥ 3.3.0 | Advanced adversarial testing |
| `cleverhans` | ≥ 4.0.0 | Additional adversarial attacks |

Install full dependencies with:

```bash
pip install -e ".[full]"
```

---

## See Also

- [Installation Guide](INSTALLATION.md) — System requirements and installation methods
- [Usage Guide](USAGE.md) — Step-by-step usage instructions and scan type details
