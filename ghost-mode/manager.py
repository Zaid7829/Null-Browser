"""
Ghost Mode Manager for Null Browser.

Coordinates:
- Lifecycle State Machine (DISABLED -> STARTING -> TOR_BOOTSTRAPPING -> READY -> STOPPING -> DISABLED)
- Tor Process Supervisor (monitors official Tor daemon, bootstrap, fail-closed)
- Ghost Profile Manager (ephemeral profile creation, user.js SOCKS5 routing, cleanup)
- Privileged Diagnostics (factual status, security boundary enforcement)

Ensures Ghost Mode is strictly OPTIONAL and never becomes default.
"""

import os
import subprocess
import threading
from typing import List, Optional

from .mode.state import GhostLifecycleStateMachine, GhostState, StateTransitionError
from .tor.supervisor import (
    TorConfig,
    TorSupervisor,
    TorSupervisorError,
    TorExecutableNotFoundError,
    TorBootstrapError,
    TorPortConflictError,
    TorProcessState,
)
from .profile.profile_manager import GhostProfileManager
from .diagnostics.diagnostics import GhostDiagnostics


class GhostModeError(Exception):
    """Base exception for Ghost Mode operations."""
    pass


class GhostModeManager:
    """Central manager coordinating Ghost Mode activation, supervision, and isolation."""

    def __init__(
        self,
        tor_config: Optional[TorConfig] = None,
        downloads_dir: Optional[str] = None,
    ):
        self._lock = threading.RLock()
        self.state_machine = GhostLifecycleStateMachine(initial_state=GhostState.DISABLED)

        # Initialize Tor supervisor with callbacks for unexpected exit
        self.supervisor = TorSupervisor(
            config=tor_config,
            on_unexpected_exit=self._handle_tor_unexpected_exit,
            on_bootstrap_progress=self._handle_tor_bootstrap_progress,
        )

        # Initialize Ephemeral Profile Manager
        self.profile_manager = GhostProfileManager(
            socks_host=self.supervisor.config.socks_host,
            socks_port=self.supervisor.config.socks_port or 9050,
            downloads_dir=downloads_dir,
        )

        # Diagnostics provider
        self.diagnostics = GhostDiagnostics(
            state_machine=self.state_machine,
            supervisor=self.supervisor,
            profile_manager=self.profile_manager,
        )

        self._active_profile_path: Optional[str] = None
        self._firefox_process: Optional[subprocess.Popen] = None

    @property
    def is_ghost_mode_active(self) -> bool:
        """Returns True only when Ghost Mode is active or transitioning."""
        return self.state_machine.is_active

    @property
    def is_ghost_mode_ready(self) -> bool:
        """Returns True only when Tor is bootstrapped and ephemeral profile is ready."""
        return self.state_machine.is_ready

    @property
    def current_state(self) -> GhostState:
        return self.state_machine.current_state

    @property
    def active_profile_path(self) -> Optional[str]:
        return self._active_profile_path

    @property
    def last_error(self) -> Optional[str]:
        return self.state_machine.last_error

    @property
    def is_firefox_running(self) -> bool:
        with self._lock:
            return self._firefox_process is not None and self._firefox_process.poll() is None

    def enable_ghost_mode(self) -> str:
        """
        Activates Ghost Mode:
        1. Transitions state DISABLED -> STARTING.
        2. Spawns Tor and transitions STARTING -> TOR_BOOTSTRAPPING.
        3. Waits for Tor to reach 100% bootstrap and verifies owned SOCKS listener.
        4. Synchronizes ephemeral profile with active Tor SOCKS port.
        5. Transitions TOR_BOOTSTRAPPING -> READY.
        6. Returns ephemeral profile directory path.

        FAIL-CLOSED: If Tor binary is missing, fails to bootstrap, or errors,
        aborts cleanly, cleans up any partial state, and transitions back to DISABLED.
        """
        with self._lock:
            if self.state_machine.is_active:
                if self.state_machine.is_ready and self._active_profile_path:
                    return self._active_profile_path
                raise GhostModeError("Ghost Mode is already in the process of starting or active.")

            # Step 1: STARTING
            self.state_machine.transition_to(GhostState.STARTING)

            try:
                # Step 2: Supervise Tor
                self.state_machine.transition_to(GhostState.TOR_BOOTSTRAPPING)
                self.supervisor.start()

                # Step 3: Create isolated ephemeral profile pointing to the verified active SOCKS port
                active_port = self.supervisor.active_socks_port or self.supervisor.config.socks_port
                self.profile_manager.socks_port = active_port
                profile_dir = self.profile_manager.create_ephemeral_profile()
                self._active_profile_path = profile_dir

                # Step 4: READY
                self.state_machine.transition_to(GhostState.READY)
                return profile_dir

            except Exception as e:
                # Fail-closed cleanup
                err_msg = str(e)
                self._cleanup_on_failure(err_msg)
                raise GhostModeError(f"Ghost Mode failed to enable: {err_msg}") from e

    def disable_ghost_mode(self, preserve_downloads: bool = True) -> None:
        """
        Deactivates Ghost Mode:
        1. Transitions READY/STARTING -> STOPPING.
        2. Terminates owned Firefox session if running.
        3. Cleans up ephemeral profile (strictly preserving downloads).
        4. Stops Tor process supervisor and verifies process termination.
        5. Transitions STOPPING -> DISABLED.
        """
        with self._lock:
            if self.state_machine.current_state == GhostState.DISABLED:
                return

            try:
                self.state_machine.transition_to(GhostState.STOPPING)
            except StateTransitionError:
                # If in abnormal state, force reset
                self.state_machine.force_reset("Disabling from abnormal state")

            # Terminate owned Firefox process
            self._terminate_firefox()

            # Clean up ephemeral profile data
            if self._active_profile_path:
                self.profile_manager.cleanup(self._active_profile_path)
                self._active_profile_path = None

            # Stop Tor daemon
            self.supervisor.stop()

            # Transition to DISABLED
            try:
                self.state_machine.transition_to(GhostState.DISABLED)
            except StateTransitionError:
                self.state_machine.force_reset()

    def launch_firefox(
        self,
        firefox_binary: str,
        additional_args: Optional[List[str]] = None,
        env: Optional[dict] = None,
        stdout=None,
        stderr=None,
    ) -> subprocess.Popen:
        """
        Launches Firefox in Ghost Mode with dedicated ephemeral profile and session isolation.
        Tracks the launched process to ensure fail-closed termination.
        """
        with self._lock:
            if not self.state_machine.is_ready or not self._active_profile_path:
                raise GhostModeError("Cannot launch Firefox: Ghost Mode is not ready.")

            args = [firefox_binary] + self.get_firefox_launch_args()
            if additional_args:
                args.extend(additional_args)

            try:
                proc = subprocess.Popen(args, env=env, stdout=stdout, stderr=stderr)
                self._firefox_process = proc
                return proc
            except Exception as e:
                self.disable_ghost_mode()
                raise GhostModeError(f"Failed to launch Firefox in Ghost Mode: {e}") from e

    def get_firefox_launch_args(self) -> List[str]:
        """
        Returns the command-line arguments to pass to the Firefox executable for Ghost Mode:
        -no-remote: prevents attaching to any existing default Firefox session.
        -profile <path>: points to the dedicated isolated ephemeral profile.
        """
        with self._lock:
            if not self.state_machine.is_ready or not self._active_profile_path:
                raise GhostModeError("Cannot generate launch args: Ghost Mode is not ready.")

            return ["-no-remote", "-profile", self._active_profile_path]

    def _terminate_firefox(self) -> None:
        """Safely terminates the owned Firefox process if active."""
        proc = self._firefox_process
        self._firefox_process = None
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3.0)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=2.0)
                except Exception:
                    pass

    def _cleanup_on_failure(self, error_message: str) -> None:
        """Fail-closed rollback on startup error."""
        self._terminate_firefox()

        if self._active_profile_path:
            self.profile_manager.cleanup(self._active_profile_path)
            self._active_profile_path = None

        self.supervisor.stop()
        self.state_machine.force_reset(reason=error_message)

    def _handle_tor_unexpected_exit(self, exit_code: int, error_msg: str) -> None:
        """
        Called when Tor process terminates unexpectedly while active.
        Enforces FAIL-CLOSED: immediately terminates Firefox, wipes ephemeral profile,
        and transitions state back to DISABLED.
        """
        with self._lock:
            if self.state_machine.is_active:
                # Terminate running Firefox process immediately to prevent direct unproxied traffic
                self._terminate_firefox()

                if self._active_profile_path:
                    self.profile_manager.cleanup(self._active_profile_path)
                    self._active_profile_path = None

                self.state_machine.force_reset(
                    reason=f"Tor terminated unexpectedly (exit code {exit_code}): {error_msg}"
                )

    def _handle_tor_bootstrap_progress(self, percent: int, log_line: str) -> None:
        """Callback for bootstrap progress tracking."""
        pass
