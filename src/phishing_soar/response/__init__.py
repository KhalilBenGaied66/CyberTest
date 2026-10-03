"""Reversible, approval-gated containment adapters."""

from .safety import UnsafeTargetError, check_block_target, check_ttl
from .simulated_blocklist import ResponseError, SimulatedBlocklist

__all__ = ["ResponseError", "SimulatedBlocklist", "UnsafeTargetError", "check_block_target", "check_ttl"]
