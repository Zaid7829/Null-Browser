"""
Tor Process Supervisor for Null Browser Ghost Mode.

Supervises an official Tor binary (bundled or system-provided):
- Manages process lifecycle (spawn, bootstrap tracking, graceful shutdown).
- Dynamically allocates or verifies SOCKS5 listener on loopback.
- Enforces FAIL-CLOSED behavior: if Tor is unavailable or terminates unexpectedly,
  the supervisor alerts callers immediately and never enables direct connections.
- Strict localhost-only binding validation.
- Removes unused ControlPort to minimize attack surface.
- Verifies process ownership and protects against port collisions.
- Does NOT implement custom Tor protocols or custom cryptography.
- Does NOT fabricate fake Tor status or metrics.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Callable, Dict, List, Optional


class TorSupervisorError(Exception):
    """Base exception for Tor supervision errors."""
    pass


class TorExecutableNotFoundError(TorSupervisorError):
    """Raised when an official Tor binary cannot be located."""
    pass


class TorBootstrapError(TorSupervisorError):
    """Raised when Tor fails to bootstrap to 100% within the timeout."""
    pass


class TorPortConflictError(TorSupervisorError):
    """Raised when the target SOCKS port is already occupied or Tor fails to bind."""
    pass


ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def find_available_loopback_port(host: str = "127.0.0.1") -> int:
    """Finds an available ephemeral TCP port on the loopback interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def is_port_in_use(host: str, port: int, timeout: float = 0.5) -> bool:
    """Probes whether a TCP port is currently open and accepting connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.error, OSError):
            return False


class TorConfig:
    """Configuration parameters for the managed Tor daemon."""
    def __init__(
        self,
        binary_path: Optional[str] = None,
        socks_host: str = "127.0.0.1",
        socks_port: Optional[int] = None,  # None or 0 indicates dynamic port selection
        data_dir: Optional[str] = None,
        bootstrap_timeout_sec: float = 60.0,
    ):
        # Strict security validation: Tor listeners must NEVER bind to external interfaces
        if socks_host not in ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                f"Security violation: socks_host '{socks_host}' is not an allowed loopback interface. "
                f"Must be one of {ALLOWED_LOOPBACK_HOSTS}"
            )
        if socks_port is not None and socks_port != 0 and not (1 <= socks_port <= 65535):
            raise ValueError(f"Invalid socks_port: {socks_port}. Must be between 1 and 65535.")

        self.binary_path = binary_path
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.data_dir = data_dir
        self.bootstrap_timeout_sec = bootstrap_timeout_sec


def find_tor_binary(custom_path: Optional[str] = None) -> Optional[str]:
    """
    Locates the official Tor binary in order of precedence:
    1. Explicit custom path (canonicalized and verified)
    2. Environment variable NULL_TOR_BINARY
    3. Null Browser bundled tools directory (<repo>/tools/tor/tor.exe)
    4. System PATH
    """
    if custom_path:
        norm_path = os.path.realpath(os.path.abspath(custom_path))
        if os.path.isfile(norm_path) and os.access(norm_path, os.X_OK):
            return norm_path

    env_path = os.environ.get("NULL_TOR_BINARY")
    if env_path:
        norm_env = os.path.realpath(os.path.abspath(env_path))
        if os.path.isfile(norm_env) and os.access(norm_env, os.X_OK):
            return norm_env

    # Check bundled location
    repo_root = os.path.realpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    binary_name = "tor.exe" if sys.platform == "win32" else "tor"
    bundled_candidate = os.path.join(repo_root, "tools", "tor", binary_name)
    if os.path.isfile(bundled_candidate) and os.access(bundled_candidate, os.X_OK):
        return os.path.realpath(bundled_candidate)

    # Check system PATH
    system_candidate = shutil.which("tor")
    if system_candidate and os.path.isfile(system_candidate):
        return os.path.realpath(os.path.abspath(system_candidate))

    return None


class TorSupervisor:
    """
    Supervises a real Tor executable process.
    Provides strict fail-closed lifecycle monitoring.
    """

    BOOTSTRAP_PATTERN = re.compile(r"Bootstrapped\s+(\d+)%")
    BIND_ERROR_PATTERN = re.compile(r"(?:Could not bind to|Address already in use|Failed to bind)")

    def __init__(
        self,
        config: Optional[TorConfig] = None,
        on_unexpected_exit: Optional[Callable[[int, str], None]] = None,
        on_bootstrap_progress: Optional[Callable[[int, str], None]] = None,
    ):
        self.config = config or TorConfig()
        self.on_unexpected_exit = on_unexpected_exit
        self.on_bootstrap_progress = on_bootstrap_progress

        self._lock = threading.RLock()
        self._process: Optional[subprocess.Popen] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._bootstrapped: bool = False
        self._bootstrap_percent: int = 0
        self._is_stopping: bool = False
        self._last_error: Optional[str] = None
        self._stdout_lines: List[str] = []
        self._active_socks_port: Optional[int] = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    @property
    def is_bootstrapped(self) -> bool:
        with self._lock:
            return self.is_running and self._bootstrapped

    @property
    def bootstrap_percent(self) -> int:
        with self._lock:
            return self._bootstrap_percent

    @property
    def pid(self) -> Optional[int]:
        with self._lock:
            return self._process.pid if self._process else None

    @property
    def last_error(self) -> Optional[str]:
        with self._lock:
            return self._last_error

    @property
    def active_socks_port(self) -> Optional[int]:
        with self._lock:
            return self._active_socks_port

    def is_available(self) -> bool:
        """Checks if a verified Tor binary is available on the host system."""
        binary = find_tor_binary(self.config.binary_path)
        return binary is not None

    def start(self) -> None:
        """
        Launches the Tor daemon process and blocks until bootstrapped to 100%.
        Dynamically allocates loopback port if not specified, or checks for port conflict.
        Raises TorExecutableNotFoundError if no Tor binary exists.
        Raises TorPortConflictError if port is already occupied or bind fails.
        Raises TorBootstrapError if bootstrap fails or times out.
        """
        with self._lock:
            if self.is_running:
                return

            binary = find_tor_binary(self.config.binary_path)
            if not binary:
                self._last_error = "Tor binary not found (bundled or system). Fail-closed: Ghost Mode cannot start."
                raise TorExecutableNotFoundError(self._last_error)

            # Determine SOCKS port: dynamic allocation if None/0
            if self.config.socks_port is None or self.config.socks_port == 0:
                target_port = find_available_loopback_port(self.config.socks_host)
                self.config.socks_port = target_port
            else:
                target_port = self.config.socks_port

            # Pre-flight check: ensure target port is not already occupied by another process
            if is_port_in_use(self.config.socks_host, target_port):
                self._last_error = (
                    f"Port conflict: SOCKS listener {self.config.socks_host}:{target_port} "
                    f"is already occupied before starting Tor. Refusing to launch."
                )
                raise TorPortConflictError(self._last_error)

            self.config.binary_path = binary
            self._active_socks_port = target_port
            self._is_stopping = False
            self._bootstrapped = False
            self._bootstrap_percent = 0
            self._last_error = None
            self._stdout_lines.clear()

            # ControlPort is explicitly omitted: Null Browser does not require or use ControlPort in Step 8
            cmd = [
                binary,
                "--SocksPort", f"{self.config.socks_host}:{target_port}",
                "--AvoidDiskWrites", "1",
            ]

            if self.config.data_dir:
                os.makedirs(self.config.data_dir, exist_ok=True)
                cmd.extend(["--DataDirectory", self.config.data_dir])

            try:
                creationflags = 0
                if sys.platform == "win32":
                    creationflags = subprocess.CREATE_NO_WINDOW

                self._process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=creationflags,
                )
            except Exception as e:
                self._last_error = f"Failed to spawn Tor process: {e}"
                raise TorSupervisorError(self._last_error) from e

            # Start background reader / monitor thread
            ready_event = threading.Event()
            failure_event = threading.Event()

            self._monitor_thread = threading.Thread(
                target=self._run_monitor,
                args=(ready_event, failure_event),
                name="TorProcessMonitor",
                daemon=True,
            )
            self._monitor_thread.start()

        # Wait for bootstrap completion
        timeout = self.config.bootstrap_timeout_sec
        success = ready_event.wait(timeout=timeout)

        # Process ownership verification: our spawned process MUST still be alive!
        with self._lock:
            proc_alive = self._process is not None and self._process.poll() is None

        if not success or not proc_alive:
            err_msg = self._last_error or "Tor process failed to bootstrap or exited prematurely."
            self.stop()
            if "Port conflict" in err_msg or "bind" in err_msg.lower():
                raise TorPortConflictError(err_msg)
            raise TorBootstrapError(err_msg)

        # Confirm SOCKS listener port is responding
        if not self._probe_socks_listener(self.config.socks_host, target_port, timeout=3.0):
            self.stop()
            raise TorSupervisorError(
                f"Tor SOCKS listener {self.config.socks_host}:{target_port} not responding after bootstrap."
            )

    def stop(self) -> None:
        """Gracefully terminates the Tor process and terminates its process tree."""
        with self._lock:
            self._is_stopping = True
            proc = self._process
            self._process = None
            self._bootstrapped = False
            self._bootstrap_percent = 0
            self._active_socks_port = None

        if proc and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    if sys.platform == "win32":
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    else:
                        proc.kill()
                    proc.wait(timeout=2.0)
            except Exception:
                pass

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)
            self._monitor_thread = None

    def get_status(self) -> Dict[str, object]:
        """
        Returns a sanitized diagnostics dictionary distinguishing process,
        bootstrap, and socket state without claiming unverified network connectivity.
        """
        with self._lock:
            active_port = self._active_socks_port or self.config.socks_port
            listener_str = f"{self.config.socks_host}:{active_port}" if active_port else "not_configured"
            return {
                "available": self.is_available(),
                "binary_path": self.config.binary_path,
                "process_running": self.is_running,
                "pid": self.pid,
                "socks_listener": listener_str,
                "bootstrapped_100": self._bootstrapped,
                "bootstrap_percent": self._bootstrap_percent,
                "last_error": self._last_error,
            }

    def _run_monitor(self, ready_event: threading.Event, failure_event: threading.Event) -> None:
        """Reads Tor stdout, monitors bootstrap, detects bind errors, and tracks termination."""
        proc = self._process
        if not proc or not proc.stdout:
            failure_event.set()
            return

        try:
            for line in iter(proc.stdout.readline, ""):
                line_str = line.strip()
                if not line_str:
                    continue

                with self._lock:
                    self._stdout_lines.append(line_str)
                    if len(self._stdout_lines) > 200:
                        self._stdout_lines.pop(0)

                # Check for port bind errors
                if self.BIND_ERROR_PATTERN.search(line_str):
                    with self._lock:
                        self._last_error = f"Tor bind failure: {line_str}"
                    failure_event.set()

                # Check bootstrap progress
                m = self.BOOTSTRAP_PATTERN.search(line_str)
                if m:
                    percent = int(m.group(1))
                    with self._lock:
                        self._bootstrap_percent = percent
                    if self.on_bootstrap_progress:
                        try:
                            self.on_bootstrap_progress(percent, line_str)
                        except Exception:
                            pass

                    if percent >= 100:
                        with self._lock:
                            self._bootstrapped = True
                        ready_event.set()

        except Exception as e:
            with self._lock:
                self._last_error = f"Monitor read error: {e}"
        finally:
            proc.stdout.close()
            exit_code = proc.wait()

            with self._lock:
                was_stopping = self._is_stopping
                self._bootstrapped = False
                if not was_stopping:
                    self._last_error = f"Tor process terminated unexpectedly with exit code {exit_code}"

            failure_event.set()

            if not was_stopping and self.on_unexpected_exit:
                try:
                    self.on_unexpected_exit(exit_code, self._last_error or "Unexpected termination")
                except Exception:
                    pass

    @staticmethod
    def _probe_socks_listener(host: str, port: int, timeout: float = 2.0) -> bool:
        """Verifies that the SOCKS5 TCP listener is open and accepting sockets."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.close()
            return True
        except (socket.error, OSError):
            return False
