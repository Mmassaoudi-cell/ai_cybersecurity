# Repository Structure

This document describes the structure of the AI Cybersecurity Platform repository.

```
ai-cybersecurity-platform/
├── .github/                    # GitHub configuration
│   └── ISSUE_TEMPLATE/         # Issue templates
├── ai_cybersecurity/           # Core package
│   ├── __init__.py            # Package initialization
│   ├── ml_scanner.py          # ML model vulnerability scanner
│   ├── agent_scanner.py       # AI agent vulnerability scanner
│   ├── immunization.py        # Model immunization module
│   ├── integration.py         # External tool integration
│   ├── reporting.py           # Report generation
│   ├── utils.py               # Utility functions
│   └── cli.py                 # Command-line interface
├── docs/                       # Documentation
│   ├── INSTALLATION.md        # Installation guide
│   └── USAGE.md               # Usage guide
├── releases/                   # Pre-built executables
│   ├── AI_Cybersecurity_Platform_Enhanced_Final.exe
│   └── README.md
├── templates/                  # Report templates
│   └── report.html            # HTML report template
├── .gitignore                  # Git ignore rules
├── CHANGELOG.md                # Version history
├── CONTRIBUTING.md             # Contribution guidelines
├── LICENSE                     # MIT License
├── README.md                   # Main documentation
├── REPOSITORY_STRUCTURE.md     # This file
├── architecture_diagram.svg    # Architecture visualization
├── logo.png                    # Application logo
├── main.py                     # GUI application entry point
├── requirements.txt            # Python dependencies
├── setup.py                    # Package setup script
└── AI_Cybersecurity_Platform_Enhanced_Final.spec  # PyInstaller spec

```

## Key Files

### Core Application
- **main.py**: Main GUI application entry point
- **ai_cybersecurity/**: Core package containing all scanning and immunization logic

### Executables
- **releases/**: Contains pre-built Windows executables
- **AI_Cybersecurity_Platform_Enhanced_Final.spec**: PyInstaller configuration

### Documentation
- **README.md**: Main project documentation
- **docs/**: Detailed guides and references
- **CHANGELOG.md**: Version history
- **CONTRIBUTING.md**: Contribution guidelines

### Configuration
- **requirements.txt**: Python package dependencies
- **setup.py**: Package installation configuration
- **.gitignore**: Git ignore patterns

### Resources
- **logo.png**: Application logo
- **templates/**: Report generation templates
- **architecture_diagram.svg**: Visual architecture diagram

## Building the Executable

To build the executable from source:

```bash
pip install pyinstaller
pyinstaller --clean AI_Cybersecurity_Platform_Enhanced_Final.spec
```

The executable will be created in `dist/` directory.

