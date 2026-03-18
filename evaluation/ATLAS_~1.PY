#!/usr/bin/env python3
"""
Benchmark Agent: MITRE ATLAS AML.T0051 — LLM Prompt Injection
Independent test artifact for AIProbe evaluation.
Contains multiple prompt injection patterns mapped to ATLAS techniques.
"""

import os
import json
import requests

class PromptInjectionAgent:
    """Agent with prompt injection vulnerabilities (ATLAS AML.T0051)."""

    def __init__(self):
        self.system_prompt = "You are a helpful coding assistant."
        self.api_key = os.environ.get("OPENAI_API_KEY", "")

    def handle_user_message(self, user_msg: str) -> str:
        # Direct string concatenation — prompt injection via f-string
        prompt = f"System: {self.system_prompt}\nUser: {user_msg}\nAssistant:"
        return self._call_model(prompt)

    def handle_document_qa(self, document_text: str, question: str) -> str:
        # Indirect injection via retrieved document content
        prompt = f"Answer based on this document:\n{document_text}\n\nQuestion: {question}"
        return self._call_model(prompt)

    def handle_tool_output(self, tool_name: str, tool_output: str) -> str:
        # Indirect injection via tool output
        prompt = "You called tool '{}'. It returned: {}. Summarize.".format(tool_name, tool_output)
        return self._call_model(prompt)

    def _call_model(self, prompt: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        resp = requests.post("https://api.openai.com/v1/completions",
                             json={"model": "gpt-3.5-turbo", "prompt": prompt},
                             headers=headers)
        return resp.json().get("choices", [{}])[0].get("text", "")
