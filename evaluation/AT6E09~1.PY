#!/usr/bin/env python3
"""
Benchmark Agent: MITRE ATLAS AML.T0040 — ML Model Access / Missing Authorization
Independent test artifact for AIProbe evaluation.
Contains missing authorization and access control patterns.
"""

import requests
import json

class NoAuthAgent:
    """Agent lacking proper authorization controls."""

    def __init__(self):
        self.api_url = "https://internal-api.example.com"
        # Vulnerability: hardcoded credentials
        self.token = "hardcoded_admin_token_xyz"

    def query_model(self, input_data: dict) -> dict:
        # Vulnerability: no authentication check on incoming requests
        resp = requests.post(
            f"{self.api_url}/predict",
            json=input_data,
            headers={"Authorization": f"Bearer {self.token}"},
            verify=False  # Vulnerability: SSL verification disabled
        )
        return resp.json()

    def update_model(self, model_bytes: bytes):
        # Vulnerability: no role check — any caller can update the model
        with open("model.pkl", "wb") as f:
            f.write(model_bytes)

    def get_training_data(self):
        # Vulnerability: sensitive data exposure without access control
        with open("training_data.csv") as f:
            return f.read()

    def admin_panel(self, command: str):
        # Vulnerability: admin functionality with no authorization gate
        if command == "reset":
            return "System reset."
        elif command == "export_users":
            return json.dumps({"users": ["admin", "user1", "user2"]})
