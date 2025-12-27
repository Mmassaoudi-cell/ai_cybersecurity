# 🛡️ AI Cybersecurity Platform

**A Unified Platform for Automated Cybersecurity Vulnerability Assessment in Machine Learning Models and AI Agents**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/ai-cybersecurity/ai-cybersecurity-platform)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/ai-cybersecurity/ai-cybersecurity-platform)

## 📋 Overview

The AI Cybersecurity Platform is a comprehensive tool designed to identify and assess cybersecurity vulnerabilities in Machine Learning models and AI agents. Developed by researchers at Texas A&M University, this platform addresses the growing need for automated security assessment in AI systems.

### 🎯 Key Features

- **ML Model Security Assessment**
  - Insecure serialization detection (Pickle, joblib)
  - Malicious payload scanning
  - Adversarial robustness testing
  - Framework-specific vulnerability detection
  - Model metadata and provenance analysis

- **AI Agent Security Analysis**
  - Prompt injection vulnerability detection
  - Unsafe code execution analysis
  - Authorization and access control assessment
  - Goal manipulation vulnerability scanning
  - Inter-agent communication security
  - Supply chain dependency analysis

- **Model Immunization & Automated Remediation**
  - Secure serialization conversion (Pickle → ONNX/SavedModel)
  - Automated adversarial training (FGSM, PGD, C&W, DeepFool)
  - Input sanitization and code refactoring
  - AES-256 encryption with integrity verification
  - Differential privacy mechanisms

- **Professional Reporting**
  - Multiple output formats (HTML, JSON, Text)
  - Risk scoring and severity categorization
  - Actionable remediation guidance
  - CVE integration and reference links

- **User-Friendly Interface**
  - Modern GUI application (Tkinter-based)
  - Command-line interface (CLI)
  - Batch processing capabilities
  - Real-time progress tracking

## 🚀 Quick Start

### Option 1: Run the Executable (Recommended for Windows)

1. **Download the latest release** from the [releases page](https://github.com/ai-cybersecurity/ai-cybersecurity-platform/releases)
2. **Extract** the files to your desired location
3. **Run** `AI_Cybersecurity_Platform_Enhanced_Final.exe` from the `releases/` folder

**Note**: The executable is a standalone application (774MB) that includes all dependencies. No Python installation required.

### Option 2: Build from Source

1. **Clone the repository**
   ```bash
   git clone https://github.com/ai-cybersecurity/ai-cybersecurity-platform.git
   cd ai-cybersecurity-platform
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   # GUI version
   python main.py
   
   # CLI version
   python -m ai_cybersecurity.cli --help
   ```

4. **Build executable (Windows)**
   ```bash
   # Using PyInstaller
   pyinstaller AI_Cybersecurity_Platform_Enhanced_Final.spec
   ```

## 💻 Usage

### GUI Application

1. **Launch** `AI_Cybersecurity_Platform_Enhanced_Final.exe` or run `python main.py`
2. **Browse** to select your ML model or AI agent file
3. **Choose** scan type (Auto-detect, ML Model, or AI Agent)
4. **Click** "Start Scan" to begin analysis
5. **Review** results in the interactive table
6. **Click** "Immunize Model" to apply automated remediation (if vulnerabilities detected)
7. **Generate** detailed reports in your preferred format (HTML, JSON, Text)

### Command Line Interface

```bash
# Scan an ML model
python -m ai_cybersecurity.cli scan-model path/to/model.pkl --format table --verbose

# Scan an AI agent
python -m ai_cybersecurity.cli scan-agent path/to/agent.py --format json --output report.json

# Display platform information
python -m ai_cybersecurity.cli info
```

### Supported File Formats

| Type | Extensions | Description |
|------|------------|-------------|
| **ML Models** | `.pkl`, `.pickle`, `.joblib` | Python pickle/joblib serialized models |
| | `.h5`, `.hdf5` | TensorFlow/Keras HDF5 models |
| | `.onnx` | ONNX format models |
| | `.pth`, `.pt` | PyTorch models |
| | `.pb` | TensorFlow SavedModel |
| **AI Agents** | `.py` | Python script files |

## 🔍 Vulnerability Categories

### ML Model Vulnerabilities

- **🔴 Critical**: Malicious payload execution, arbitrary code injection
- **🟠 High**: Insecure serialization, adversarial vulnerabilities
- **🟡 Medium**: Missing explainability, large file sizes
- **🟢 Low**: Missing metadata, file permission issues

### AI Agent Vulnerabilities

- **🔴 Critical**: Unsafe code execution (eval, exec)
- **🟠 High**: Prompt injection, authorization bypass, goal manipulation
- **🟡 Medium**: Insecure communication, resource management issues
- **🟢 Low**: Missing authentication, supply chain warnings

## 🛡️ Model Immunization

The platform provides automated remediation capabilities:

- **Secure Serialization**: Automatically converts Pickle models to ONNX/SavedModel
- **Adversarial Training**: Implements FGSM/PGD/C&W-based adversarial training
- **Input Sanitization**: Generates template code for prompt validation
- **Code Refactoring**: Suggests safe alternatives for eval/exec patterns
- **Encryption**: AES-256 encryption with HMAC integrity verification

**Validation Results** (15 vulnerable models):
- 93% reduction in adversarial attack success rate
- 100% elimination of insecure serialization
- 87% reduction in prompt injection surface
- 100% elimination of unsafe eval/exec patterns

## 📊 Reports and Output

The platform generates comprehensive reports with:

- **Executive Summary**: Risk score and vulnerability counts
- **Detailed Findings**: Individual vulnerability descriptions
- **Remediation Guidance**: Specific steps to fix issues
- **Reference Links**: External resources and documentation
- **Confidence Scoring**: Assessment reliability metrics

## 🏗️ Architecture

The platform is built with a modular, layered architecture:

```
AI Cybersecurity Platform
├── User Interface Layer
│   ├── GUI Application (Tkinter)
│   └── CLI Interface (Typer + Rich)
├── Application Layer
│   └── Main Application (main.py)
├── Core Scanners
│   ├── ML Scanner (pickle, framework detection, adversarial testing)
│   └── Agent Scanner (AST analysis, prompt injection, supply chain)
├── Integration Layer
│   ├── Adversarial Testing (Foolbox, CleverHans simulation)
│   ├── CVE Database (vulnerability lookup)
│   └── Framework Detection (TensorFlow, PyTorch, etc.)
├── Model Immunization Module
│   ├── Adversarial Training
│   ├── Encryption
│   ├── Secure Serialization
│   └── Differential Privacy
└── Reporting Engine
    ├── HTML Reports (web-friendly)
    ├── JSON Reports (machine-readable)
    └── Text Reports (human-readable)
```

See `architecture_diagram.svg` for a detailed visual representation.

## 🛠️ Building Executables

### Prerequisites

- Python 3.8 or later
- Windows 10/11 (for .exe generation)
- At least 2GB free disk space
- PyInstaller 5.0.0 or later

### Build Process

1. **Install PyInstaller**
   ```bash
   pip install pyinstaller>=5.0.0
   ```

2. **Run build using spec file**
   ```bash
   pyinstaller --clean AI_Cybersecurity_Platform_Enhanced_Final.spec
   ```

3. **Find your executable**
   - Location: `dist/AI_Cybersecurity_Platform_Enhanced_Final.exe`
   - Size: ~774MB (includes all dependencies)

## 📚 Documentation

- **[Installation Guide](docs/INSTALLATION.md)**: Detailed installation instructions
- **[User Guide](docs/USAGE.md)**: Comprehensive usage documentation
- **[API Reference](docs/API.md)**: Programming interface documentation
- **[Architecture Diagram](architecture_diagram.svg)**: Visual architecture overview

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/

# Run with coverage
pytest --cov=ai_cybersecurity tests/
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. **Fork and clone** the repository
2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install development dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -e ".[dev]"
   ```
4. **Run tests**
   ```bash
   pytest tests/
   ```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Mohamed Massaoudi, PhD** - *Lead Developer* - [Email](mailto:mohamed.massaoudi@tamu.edu)
- **Maymouna Ez Eddin** - *Developer*

*Department of Electrical and Computer Engineering*  
*Texas A&M University, College Station, USA*

## 🙏 Acknowledgments

- Texas A&M University
- Open source security community
- Beta testers and early adopters

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ai-cybersecurity/ai-cybersecurity-platform/issues)
- **Email**: [mohamed.massaoudi@tamu.edu](mailto:mohamed.massaoudi@tamu.edu)
- **Documentation**: See `docs/` folder

## 🔄 Changelog

### Version 1.0.0 (2024-12-27)
- Initial release
- GUI and CLI interfaces
- ML model and AI agent scanning
- Comprehensive vulnerability detection
- Model immunization and automated remediation
- Professional reporting system
- Windows executable generation

---

**⚠️ Security Notice**: This tool is designed to help identify security vulnerabilities. Always verify findings manually and follow responsible disclosure practices when reporting vulnerabilities in third-party systems.


