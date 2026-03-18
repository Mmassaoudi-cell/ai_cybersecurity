#!/usr/bin/env python3
"""
Benchmark Agent: MITRE ATLAS AML.T0048 — Command & Control / Unsafe Code Execution
Independent test artifact for AIProbe evaluation.
Contains unsafe code execution patterns.
"""

import subprocess
import ast

class UnsafeCodeAgent:
    """Agent with unsafe code execution vulnerabilities."""

    def execute_user_code(self, code_str: str):
        # Vulnerability: direct eval of user-supplied code
        return eval(code_str)

    def run_shell_command(self, cmd: str):
        # Vulnerability: shell injection
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout

    def dynamic_import(self, module_name: str):
        # Vulnerability: arbitrary module loading
        mod = __import__(module_name)
        return mod

    def compile_and_exec(self, source: str):
        # Vulnerability: compile + exec chain
        compiled = compile(source, "<user_input>", "exec")
        exec(compiled)

    def ast_eval_fallback(self, expr: str):
        """Attempt safe eval but fall back to dangerous eval."""
        try:
            return ast.literal_eval(expr)
        except (ValueError, SyntaxError):
            return eval(expr)  # Dangerous fallback
