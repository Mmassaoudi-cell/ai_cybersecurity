#!/usr/bin/env python3
"""
Benchmark Agent: MITRE ATLAS AML.T0054 — LLM Goal Hijacking / Goal Manipulation
Independent test artifact for AIProbe evaluation.
Contains goal manipulation and identity spoofing patterns.
"""

import json
import os

class GoalHijackingAgent:
    """Agent vulnerable to goal manipulation (ATLAS AML.T0054)."""

    def __init__(self):
        self.goal = "Summarize the document."
        self.role = "assistant"

    def update_goal(self, new_goal: str):
        # Vulnerability: no validation on goal change
        self.goal = new_goal

    def process_instruction(self, instruction: str) -> str:
        # Vulnerability: goal is overridable by user instruction
        full_prompt = f"Your goal is: {self.goal}\nUser instruction: {instruction}"
        return full_prompt

    def override_role(self, new_role: str):
        # Vulnerability: identity can be overridden
        self.role = new_role

    def load_config_from_user(self, config_json: str):
        # Vulnerability: user-controllable configuration
        config = json.loads(config_json)
        self.goal = config.get("goal", self.goal)
        self.role = config.get("role", self.role)

    def get_env_secrets(self):
        # Vulnerability: information disclosure through environment variables
        return {
            "api_key": os.environ.get("API_KEY", ""),
            "db_password": os.environ.get("DB_PASSWORD", ""),
        }
