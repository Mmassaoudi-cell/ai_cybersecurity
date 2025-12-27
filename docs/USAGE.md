# Usage Guide

This guide provides detailed instructions for using the AI Cybersecurity Platform.

## Quick Start

### GUI Application

1. **Launch the application**
   - Windows: Double-click `AI_Cybersecurity_Platform_Enhanced_Final.exe`
   - From source: Run `python main.py`

2. **Select a file**
   - Click "Browse" to select an ML model or AI agent file
   - Supported formats: `.pkl`, `.joblib`, `.onnx`, `.pth`, `.py`, etc.

3. **Choose scan type**
   - **Auto-detect**: Let the platform determine the file type
   - **ML Model**: Force ML model scanning
   - **AI Agent**: Force AI agent scanning

4. **Start scanning**
   - Click "Start Scan"
   - Monitor progress in the progress bar
   - Results appear in the table below

5. **Review results**
   - View vulnerabilities by severity
   - Click on rows for detailed information
   - Check remediation guidance

6. **Immunize model** (if vulnerabilities found)
   - Click "Immunize Model" button
   - Select protection methods
   - Wait for immunization to complete
   - Save the immunized model

7. **Generate report**
   - Click "Generate Report"
   - Choose format (HTML, JSON, or Text)
   - Save to desired location

### Command Line Interface

#### Basic Usage

```bash
# Scan an ML model
python -m ai_cybersecurity.cli scan-model model.pkl

# Scan an AI agent
python -m ai_cybersecurity.cli scan-agent agent.py

# Scan with specific output format
python -m ai_cybersecurity.cli scan-model model.pkl --format json --output report.json

# Verbose output
python -m ai_cybersecurity.cli scan-model model.pkl --verbose
```

#### Advanced Options

```bash
# Scan with custom configuration
python -m ai_cybersecurity.cli scan-model model.pkl \
    --config custom_config.yaml \
    --exclude-tests \
    --min-severity high

# Batch processing
python -m ai_cybersecurity.cli scan-batch models/ --output-dir reports/

# Apply immunization
python -m ai_cybersecurity.cli immunize model.pkl --output model_secure.pkl
```

## File Format Support

### ML Models
- **Pickle**: `.pkl`, `.pickle`
- **Joblib**: `.joblib`
- **TensorFlow**: `.h5`, `.hdf5`, `.pb` (SavedModel)
- **PyTorch**: `.pth`, `.pt`
- **ONNX**: `.onnx`

### AI Agents
- **Python Scripts**: `.py`

## Scan Types

### ML Model Scanning

The platform performs comprehensive security analysis:

1. **Serialization Analysis**
   - Detects insecure formats (Pickle, joblib)
   - Identifies malicious payloads
   - Validates model integrity

2. **Adversarial Robustness**
   - Tests against FGSM, PGD, C&W attacks
   - Measures attack success rates
   - Evaluates perturbation norms

3. **Framework Detection**
   - Identifies TensorFlow, PyTorch, scikit-learn models
   - Checks for framework-specific vulnerabilities
   - Validates version compatibility

4. **Metadata Analysis**
   - Extracts model information
   - Verifies provenance
   - Checks for missing security controls

### AI Agent Scanning

The platform analyzes agent code for:

1. **Prompt Injection**
   - AST-based pattern detection
   - Identifies vulnerable input handling
   - Detects injection points

2. **Code Execution**
   - Finds eval/exec usage
   - Identifies unsafe dynamic imports
   - Detects code injection risks

3. **Authorization**
   - Evaluates access control mechanisms
   - Checks for privilege escalation
   - Validates authentication

4. **Supply Chain**
   - Scans dependencies
   - Checks for known CVEs
   - Validates third-party components

## Model Immunization

### Available Protection Methods

1. **Secure Serialization**
   - Converts Pickle → ONNX or SavedModel
   - Preserves model functionality
   - Eliminates code execution risks

2. **Adversarial Training**
   - FGSM-based training
   - PGD-based training
   - C&W defense
   - Ensemble methods

3. **Input Sanitization**
   - Generates validation templates
   - Implements pattern filtering
   - Adds length restrictions

4. **Encryption**
   - AES-256 encryption
   - HMAC integrity verification
   - Secure key management

### Using Immunization

**Via GUI:**
1. Complete a vulnerability scan
2. Click "Immunize Model" button
3. Select protection methods
4. Configure protection level
5. Wait for completion
6. Save immunized model

**Via CLI:**
```bash
python -m ai_cybersecurity.cli immunize model.pkl \
    --methods adversarial-training,encryption \
    --output model_secure.pkl
```

## Report Formats

### HTML Report
- Interactive web-based format
- Color-coded severity levels
- Clickable vulnerability details
- Best for human review

### JSON Report
- Machine-readable format
- Suitable for CI/CD integration
- Easy to parse programmatically
- Best for automation

### Text Report
- Plain text format
- Terminal-friendly
- Easy to email or print
- Best for quick review

## Best Practices

1. **Regular Scanning**: Scan models before deployment
2. **Version Control**: Track scan results over time
3. **CI/CD Integration**: Automate scanning in pipelines
4. **Remediation**: Apply immunization for critical vulnerabilities
5. **Documentation**: Keep reports for compliance

## Examples

See the `examples/` folder for sample scripts and use cases.

