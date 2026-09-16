"""
Null Browser Ghost Mode Package.

Provides isolated ephemeral browsing sessions routed through Tor:
- Strict ephemeral profile creation and cleanup.
- SOCKS5 remote DNS enforcement (fails closed without leaks).
- Tor supervisor with process lifecycle tracking.
- Zero persistence (disk cache disabled, history disabled, memory only).
- Safe download preservation.
"""

from .mode.state import (
    GhostState,
    GhostLifecycleStateMachine,
    StateTransitionError,
)
from .tor.supervisor import (
    TorConfig,
    TorSupervisor,
    TorSupervisorError,
    TorExecutableNotFoundError,
    TorBootstrapError,
    TorPortConflictError,
    TorProcessState,
    find_tor_binary,
    find_available_loopback_port,
    is_port_in_use,
)
from .profile.profile_manager import GhostProfileManager
from .diagnostics.diagnostics import GhostDiagnostics
from .manager import GhostModeManager, GhostModeError

__all__ = [
    "GhostState",
    "GhostLifecycleStateMachine",
    "StateTransitionError",
    "TorConfig",
    "TorSupervisor",
    "TorSupervisorError",
    "TorExecutableNotFoundError",
    "TorBootstrapError",
    "TorPortConflictError",
    "TorProcessState",
    "find_tor_binary",
    "find_available_loopback_port",
    "is_port_in_use",
    "GhostProfileManager",
    "GhostDiagnostics",
    "GhostModeManager",
    "GhostModeError",
]
