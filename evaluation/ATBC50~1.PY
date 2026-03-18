#!/usr/bin/env python3
"""
Benchmark Agent: MITRE ATLAS — Insecure Inter-Agent Communication
Independent test artifact for AIProbe evaluation.
Contains insecure communication patterns between agents.
"""

import socket
import json
import pickle

class InsecureCommAgent:
    """Agent with insecure inter-agent communication."""

    def __init__(self):
        self.peer_host = "192.168.1.100"
        self.peer_port = 9999

    def send_message(self, message: dict):
        # Vulnerability: unencrypted socket communication
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.peer_host, self.peer_port))
        # Vulnerability: pickle serialization over network
        sock.sendall(pickle.dumps(message))
        sock.close()

    def receive_message(self) -> dict:
        # Vulnerability: deserializing untrusted network data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", self.peer_port))
        sock.listen(1)
        conn, addr = sock.accept()
        data = conn.recv(65536)
        conn.close()
        sock.close()
        return pickle.loads(data)  # Unsafe deserialization

    def broadcast_state(self, state: dict):
        # Vulnerability: broadcasting sensitive state in plaintext
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(json.dumps(state).encode(), ("<broadcast>", self.peer_port))
        sock.close()

    def relay_command(self, source_agent: str, command: str):
        # Vulnerability: no origin verification
        exec(command)  # Blindly executing commands from other agents
