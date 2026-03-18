#!/usr/bin/env python3
"""
Clean Benchmark Agent — No intentional vulnerabilities.
Used to measure false positive rate.
"""

import json
import hashlib
import hmac
from typing import List, Dict, Optional


class SecureAgent:
    """A properly secured agent with no known vulnerabilities."""

    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.allowed_actions = ["summarize", "translate", "answer"]

    def _load_config(self, path: str) -> dict:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def process_request(self, action: str, payload: str) -> str:
        if action not in self.allowed_actions:
            return "Action not permitted."
        # Input is used only as data, never interpolated into prompts unsafely
        sanitized = self._sanitize(payload)
        return f"Processed: {sanitized[:200]}"

    @staticmethod
    def _sanitize(text: str) -> str:
        # Remove control characters
        return "".join(ch for ch in text if ch.isprintable())

    def verify_message(self, message: bytes, signature: bytes, key: bytes) -> bool:
        expected = hmac.new(key, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)
