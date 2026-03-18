# Repository Structure

This document describes the structure of the AIProbe repository.

```
ai_cybersecurity/
├── ai_cybersecurity/                # Core Python package
│   ├── __init__.py                  # Package init, exports, version
│   ├── ml_scanner.py                # ML model vulnerability scanner
│   ├── agent_scanner.py             # AI agent vulnerability scanner
│   ├── immunization.py              # Model immunization / remediation module
│   ├── integration.py               # External tool integration (Foolbox, CleverHans, CVE DB)
│   ├── reporting.py                 # Report generation engine
│   ├── utils.py                     # Data models (VulnerabilityReport, enums, helpers)
│   └── cli.py                       # Typer-based command-line interface
│
├── evaluation/                      # MITRE ATLAS benchmark evaluation suite
│   ├── run_atlas_evaluation.py      # Automated evaluation harness
│   ├── atlas_evaluation_results.json# Pre-computed JSON results
│   ├── benchmark_agents/            # Independently developed vulnerable agent scripts
│   │   ├── atlas_prompt_injection.py    # AML.T0051
│   │   ├── atlas_unsafe_code_exec.py    # AML.T0048
│   │   ├── atlas_goal_hijacking.py      # AML.T0054
│   │   ├── atlas_supply_chain.py        # AML.T0010
│   │   ├── atlas_no_auth.py             # AML.T0040
│   │   ├── atlas_inter_agent_comms.py   # AML.T0049
│   │   └── clean_agent.py              # Benign baseline (false-positive measurement)
│   └── benchmark_models/
│       └── benign_model.json            # Benign JSON model (false-positive measurement)
│
├── samples/                         # Sample artifacts for quick testing
│   ├── test_model.py                # Script: generate vulnerable ML models
│   ├── test_agent.py                # Intentionally vulnerable AI agent
│   ├── my_classifier.pkl            # Pickle-serialized Random Forest
│   ├── my_classifier.joblib         # Joblib-serialized Random Forest
│   ├── my_classifier.json           # Model metadata
│   └── malicious_model.pkl          # Model with embedded __reduce__ payload
│
├── templates/                       # Report templates
│   └── report.html                  # HTML report template
│
├── docs/                            # Documentation
│   ├── INSTALLATION.md              # Installation guide
│   ├── USAGE.md                     # Usage guide
│   └── API.md                       # API reference
│
├── main.py                          # GUI entry point (Tkinter)
├── requirements.txt                 # Python dependencies
├── AIProbe.spec                     # PyInstaller spec file
├── architecture_diagram.svg         # Architecture diagram
├── logo.png                         # Application logo
├── LICENSE                          # MIT License
├── CONTRIBUTING.md                  # Contribution guidelines
├── CHANGELOG.md                     # Version history
├── REPOSITORY_STRUCTURE.md          # This file
└── README.md                        # Main project documentation
```

## Key Directories

### `ai_cybersecurity/` — Core Package
Contains all scanning, immunization, integration, and reporting logic. This is the installable Python package.

### `evaluation/` — Benchmark Suite
Contains independently developed benchmark artifacts mapped to MITRE ATLAS technique categories, along with the automated evaluation harness (`run_atlas_evaluation.py`) and pre-computed results. Used to produce the results in Table 3 of the paper.

### `samples/` — Test Artifacts
Ready-to-use ML models and AI agent scripts for quick testing and demonstration. Includes both benign models (with insecure serialization) and a deliberately malicious model with an embedded code execution payload.

### `docs/` — Documentation
Installation, usage, and API reference guides.

### `templates/` — Report Templates
HTML template used by the reporting engine for generating styled vulnerability reports.

## Building the Executable

```bash
pip install pyinstaller
pyinstaller --clean AIProbe.spec
# Output: dist/AIProbe.exe
```
