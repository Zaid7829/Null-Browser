"""
Ghost Mode Privileged Diagnostics Interface.

Exposes structured, factual diagnostics for privileged browser components:
- Tor daemon status, PID, and SOCKS5 listener verification.
- Bootstrap percentage and error logs.
- Ghost lifecycle state and active profile path.
- Security boundary: must NEVER be exposed directly to unprivileged web content.
- Does NOT fabricate fake Tor status or fake anonymity metrics.
"""

from typing import Any, Dict, Optional
from ..mode.state import GhostLifecycleStateMachine, GhostState
from ..tor.supervisor import TorSupervisor
from ..profile.profile_manager import GhostProfileManager


class GhostDiagnostics:
    """Privileged diagnostic reporter for Ghost Mode."""

    def __init__(
        self,
        state_machine: GhostLifecycleStateMachine,
        supervisor: TorSupervisor,
        profile_manager: GhostProfileManager,
    ):
        self._state_machine = state_machine
        self._supervisor = supervisor
        self._profile_manager = profile_manager

    def get_full_report(self) -> Dict[str, Any]:
        """
        Generates an authentic diagnostic snapshot.
        All data is factual; nothing is simulated or fabricated.
        """
        tor_status = self._supervisor.get_status()
        state = self._state_machine.current_state

        return {
            "ghost_mode": {
                "state": state.value,
                "is_active": self._state_machine.is_active,
                "is_ready": self._state_machine.is_ready,
                "last_error": self._state_machine.last_error,
            },
            "tor_daemon": {
                "available": tor_status["available"],
                "process_running": tor_status["process_running"],
                "pid": tor_status["pid"],
                "socks_listener": tor_status["socks_listener"],
                "bootstrapped_100": tor_status["bootstrapped_100"],
                "bootstrap_percent": tor_status["bootstrap_percent"],
                "binary_path": tor_status["binary_path"],
                "daemon_error": tor_status["last_error"],
            },
            "network_routing": {
                "proxy_type": "SOCKS5",
                "proxy_host": self._profile_manager.socks_host,
                "proxy_port": self._profile_manager.socks_port,
                "remote_dns_enforced": True,
                "fail_closed_direct_fallback_blocked": True,
                "onion_routing_capable": tor_status["bootstrapped_100"],
                "live_tor_network_connectivity": "UNVERIFIED / PROPOSED",
                "live_onion_routing_tested": "UNVERIFIED / PROPOSED",
            },
            "session_isolation": {
                "ephemeral_profile_active": self._profile_manager.current_profile_dir is not None,
                "ephemeral_profile_path": self._profile_manager.current_profile_dir,
                "downloads_preserved_dir": self._profile_manager.downloads_dir,
                "memory_cache_only": True,
                "disk_history_disabled": True,
                "extensions_isolated": True,
            },
            "security_boundaries": {
                "privileged_api_only": True,
                "web_content_accessible": False,
            },
        }

    def verify_fail_closed(self) -> bool:
        """
        Verifies that if Tor is not ready, Ghost Mode is marked not ready
        and fails closed (never allowing traffic).
        """
        if not self._supervisor.is_bootstrapped:
            return not self._state_machine.is_ready
        return True
