"""
Cortensor Bounty Hunter Agent Module

This module contains the core components for autonomous issue resolution:
- AgentCoordinator: Orchestrates the workflow
- CortensorNetwork: Interfaces with the Cortensor network
- DockerSandbox: Manages sandboxed execution
- X402Merchant: Handles payment gates
"""

from agent.coordinator import AgentCoordinator
from agent.cortensor import CortensorNetwork
from agent.sandbox import DockerSandbox
from agent.x402 import X402Merchant

__all__ = [
    "AgentCoordinator",
    "CortensorNetwork", 
    "DockerSandbox",
    "X402Merchant",
]

__version__ = "0.1.0"

