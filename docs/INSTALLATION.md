# Installation Guide

This guide provides detailed instructions for installing and setting up the AI Cybersecurity Platform.

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+
- **Python**: 3.8 or higher
- **RAM**: 2GB minimum (4GB recommended)
- **Disk Space**: 1GB free space
- **Processor**: x64 architecture

### Recommended Requirements
- **OS**: Windows 11 or Ubuntu 22.04+
- **Python**: 3.10 or higher
- **RAM**: 8GB or more
- **Disk Space**: 2GB free space
- **GPU**: Optional, for faster adversarial testing

## Installation Methods

### Method 1: Using Pre-built Executable (Windows - Recommended)

1. **Download the executable**
   - Go to the [releases folder](https://github.com/ai-cybersecurity/ai-cybersecurity-platform/tree/main/releases)
   - Download `AI_Cybersecurity_Platform_Enhanced_Final.exe`

2. **Run the executable**
   - Double-click the `.exe` file
   - No installation required - it's a portable application

**Advantages:**
- No Python installation needed
- All dependencies included
- Ready to use immediately

### Method 2: Install from Source

1. **Clone the repository**
   ```bash
   git clone https://github.com/ai-cybersecurity/ai-cybersecurity-platform.git
   cd ai-cybersecurity-platform
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install the package (optional)**
   ```bash
   pip install -e .
   ```

5. **Verify installation**
   ```bash
   python -m ai_cybersecurity.cli --help
   ```

### Method 3: Install via pip (when available)

```bash
pip install ai-cybersecurity-platform
```

## Dependencies

### Core Dependencies
- `pydantic>=2.0.0` - Data validation
- `typer[all]>=0.9.0` - CLI framework
- `rich>=13.0.0` - Rich text and formatting
- `numpy>=1.20.0` - Numerical computing
- `pandas>=1.3.0` - Data analysis
- `scikit-learn>=1.0.0` - Machine learning utilities
- `cryptography>=38.0.0` - Encryption support
- `Pillow>=9.0.0` - Image processing

### Optional Dependencies
For full functionality, you may want to install:
- `torch>=1.10.0` - PyTorch support
- `tensorflow>=2.8.0` - TensorFlow support
- `foolbox>=3.3.0` - Advanced adversarial testing
- `cleverhans>=4.0.0` - Additional adversarial attacks

Install with:
```bash
pip install -e ".[full]"
```

## Troubleshooting

### Common Issues

**Issue**: "Module not found" errors
- **Solution**: Ensure all dependencies are installed: `pip install -r requirements.txt`

**Issue**: Executable won't run on Windows
- **Solution**: Check Windows Defender isn't blocking it. Right-click → Properties → Unblock

**Issue**: Import errors with cryptography
- **Solution**: Update pip and reinstall: `pip install --upgrade pip cryptography`

**Issue**: GUI doesn't display logo
- **Solution**: Ensure `logo.png` is in the same directory as the executable

**Issue**: Immunization feature not working
- **Solution**: Ensure `cryptography` and `scipy` are properly installed

## Verification

After installation, verify everything works:

```bash
# Test CLI
python -m ai_cybersecurity.cli info

# Test GUI
python main.py

# Run tests (if available)
pytest tests/
```

## Next Steps

- Read the [Usage Guide](USAGE.md)
- Check the [API Reference](API.md)
- Review [Examples](../examples/)

