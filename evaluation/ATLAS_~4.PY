#!/usr/bin/env python3
"""
Benchmark Agent: MITRE ATLAS AML.T0010 — ML Supply Chain Compromise
Independent test artifact for AIProbe evaluation.
Contains supply chain vulnerability patterns (dependency issues, unsafe imports).
"""

import pip
import importlib

class SupplyChainAgent:
    """Agent with supply chain vulnerabilities (ATLAS AML.T0010)."""

    def install_dependency(self, package_name: str):
        # Vulnerability: arbitrary package installation from user input
        pip.main(["install", package_name])

    def load_external_model(self, url: str):
        # Vulnerability: loading model from untrusted URL
        import urllib.request
        urllib.request.urlretrieve(url, "downloaded_model.pkl")
        import pickle
        with open("downloaded_model.pkl", "rb") as f:
            return pickle.load(f)  # Unsafe deserialization of remote content

    def dynamic_plugin_load(self, module_path: str):
        # Vulnerability: loading arbitrary code as plugin
        spec = importlib.util.spec_from_file_location("plugin", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def check_requirements(self, requirements_path: str):
        # Vulnerability: no pinned versions, no hash verification
        with open(requirements_path) as f:
            for line in f:
                package = line.strip()
                if package and not package.startswith("#"):
                    pip.main(["install", package])
