"""
Tor Process Supervisor for Null Browser Ghost Mode.

Supervises an official Tor binary (bundled or system-provided):
- Manages process lifecycle (spawn, bootstrap tracking, graceful shutdown).
- Enforces explicit 6-stage lifecycle state machine:
  STOPPED -> PROCESS_STARTED -> BOOTSTRAPPING -> BOOTSTRAPPED_100 -> SOCKS_READY -> FAILED
- Dynamically allocates loopback SOCKS5 listener on 127.0.0.1.
- Verifies listener process ownership (ensures listener belongs to the spawned Tor PID).
- Enforces FAIL-CLOSED behavior: if Tor is unavailable or terminates unexpectedly,
  the supervisor alerts callers immediately and never enables direct connections.
- Strict localhost-only binding validation.
- Removes unused ControlPort to minimize attack surface (--ControlPort 0).
- Completely isolates configuration by supplying an empty torrc via -f and --defaults-torrc.
- Uses dedicated ephemeral data directory, cleaned up completely upon shutdown.
- Does NOT implement custom Tor protocols or custom cryptography.
- Does NOT fabricate fake Tor status or metrics.
"""

from enum import Enum
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple


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


class TorProcessState(str, Enum):
    """Distinct internal lifecycle states for the supervised Tor daemon."""
    STOPPED = "STOPPED"
    PROCESS_STARTED = "PROCESS_STARTED"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    BOOTSTRAPPED_100 = "BOOTSTRAPPED_100"
    SOCKS_READY = "SOCKS_READY"
    FAILED = "FAILED"


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


def get_default_geoip_paths() -> Tuple[Optional[str], Optional[str]]:
    """Resolves the bundled tools/tor/geoip and geoip6 data paths if present."""
    repo_root = os.path.realpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    geoip = os.path.join(repo_root, "tools", "tor", "geoip")
    geoip6 = os.path.join(repo_root, "tools", "tor", "geoip6")
    g4 = geoip if os.path.isfile(geoip) else None
    g6 = geoip6 if os.path.isfile(geoip6) else None
    return g4, g6


class TorConfig:
    """Configuration parameters for the managed Tor daemon."""
    def __init__(
        self,
        binary_path: Optional[str] = None,
        socks_host: str = "127.0.0.1",
        socks_port: Optional[int] = None,  # None or 0 indicates dynamic port selection
        data_dir: Optional[str] = None,
        geoip_path: Optional[str] = None,
        geoip6_path: Optional[str] = None,
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

        default_g4, default_g6 = get_default_geoip_paths()

        self.binary_path = binary_path
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.data_dir = data_dir
        self.geoip_path = geoip_path or default_g4
        self.geoip6_path = geoip6_path or default_g6
        self.bootstrap_timeout_sec = bootstrap_timeout_sec


def find_tor_binary(custom_path: Optional[str] = None) -> Optional[str]:
    """
    Locates the official Tor binary in order of precedence:
    1. Explicit custom path (canonicalized and verified; fails closed if invalid)
    2. Environment variable NULL_TOR_BINARY
    3. Null Browser bundled tools directory (<repo>/tools/tor/tor.exe)
    4. System PATH
    """
    if custom_path:
        norm_path = os.path.realpath(os.path.abspath(custom_path))
        if os.path.isfile(norm_path) and os.access(norm_path, os.X_OK):
            return norm_path
        return None

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


def _is_pid_descendant_win32(child_pid: int, ancestor_pid: int) -> bool:
    """Verifies whether child_pid is equal to or a descendant of ancestor_pid on Windows."""
    if child_pid == ancestor_pid:
        return True
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        TH32CS_SNAPPROCESS = 0x00000002
        h_snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if h_snap == -1 or h_snap == 0xFFFFFFFF:
            return False

        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        parents = {}
        if kernel32.Process32First(h_snap, ctypes.byref(pe)):
            while True:
                parents[pe.th32ProcessID] = pe.th32ParentProcessID
                if not kernel32.Process32Next(h_snap, ctypes.byref(pe)):
                    break
        kernel32.CloseHandle(h_snap)

        cur = child_pid
        for _ in range(25):
            p = parents.get(cur)
            if not p or p == cur:
                break
            if p == ancestor_pid:
                return True
            cur = p
    except Exception:
        pass
    return False


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
        self._process_state: TorProcessState = TorProcessState.STOPPED
        self._bootstrapped: bool = False
        self._bootstrap_percent: int = 0
        self._is_stopping: bool = False
        self._last_error: Optional[str] = None
        self._stdout_lines: List[str] = []
        self._active_socks_port: Optional[int] = None
        self._ephemeral_data_dir: Optional[str] = None
        self._stop_event: threading.Event = threading.Event()
        self._ready_event: Optional[threading.Event] = None

    @property
    def process_state(self) -> TorProcessState:
        with self._lock:
            return self._process_state

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    @property
    def is_bootstrapped(self) -> bool:
        with self._lock:
            return self.is_running and self._bootstrapped

    @property
    def is_socks_ready(self) -> bool:
        with self._lock:
            return self.is_running and self._process_state == TorProcessState.SOCKS_READY

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
        Launches the Tor daemon process and blocks until bootstrapped to 100%
        and the owned SOCKS listener is confirmed.
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
                self._process_state = TorProcessState.FAILED
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
                self._process_state = TorProcessState.FAILED
                self._last_error = (
                    f"Port conflict: SOCKS listener {self.config.socks_host}:{target_port} "
                    f"is already occupied before starting Tor. Refusing to launch."
                )
                raise TorPortConflictError(self._last_error)

            # Establish dedicated ephemeral data directory if none specified
            if not self.config.data_dir:
                self._ephemeral_data_dir = tempfile.mkdtemp(prefix="null_ghost_tordata_")
                self.config.data_dir = self._ephemeral_data_dir
            else:
                os.makedirs(self.config.data_dir, exist_ok=True)

            canonical_data_dir = os.path.realpath(os.path.abspath(self.config.data_dir))
            empty_torrc_path = os.path.join(canonical_data_dir, "torrc_empty")
            if not os.path.exists(empty_torrc_path):
                with open(empty_torrc_path, "w", encoding="utf-8") as f:
                    f.write("# Null Browser Ghost Mode isolated empty configuration\n")

            self.config.binary_path = binary
            self._active_socks_port = target_port
            self._is_stopping = False
            self._bootstrapped = False
            self._bootstrap_percent = 0
            self._last_error = None
            self._stdout_lines.clear()
            self._process_state = TorProcessState.PROCESS_STARTED

            # Build command-line with strict configuration isolation
            cmd = [
                binary,
                "-f", empty_torrc_path,
                "--defaults-torrc", empty_torrc_path,
                "--SocksPort", f"{self.config.socks_host}:{target_port}",
                "--ControlPort", "0",
                "--DataDirectory", canonical_data_dir,
                "--AvoidDiskWrites", "1",
                "--ClientOnly", "1",
            ]

            if self.config.geoip_path and os.path.isfile(self.config.geoip_path):
                cmd.extend(["--GeoIPFile", self.config.geoip_path])
            if self.config.geoip6_path and os.path.isfile(self.config.geoip6_path):
                cmd.extend(["--GeoIPv6File", self.config.geoip6_path])

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
                self._process_state = TorProcessState.FAILED
                self._last_error = f"Failed to spawn Tor process: {e}"
                self._cleanup_ephemeral_dir()
                raise TorSupervisorError(self._last_error) from e

            # Start background reader / monitor thread
            self._stop_event.clear()
            ready_event = threading.Event()
            self._ready_event = ready_event
            failure_event = threading.Event()

            self._monitor_thread = threading.Thread(
                target=self._run_monitor,
                args=(ready_event, failure_event),
                name="TorProcessMonitor",
                daemon=True,
            )
            self._monitor_thread.start()

        # Wait for bootstrap completion, failure, or early stop
        timeout = self.config.bootstrap_timeout_sec
        start_time = time.time()
        success = False
        while time.time() - start_time < timeout:
            if self._stop_event.is_set():
                break
            if ready_event.wait(timeout=0.2):
                success = True
                break
            if failure_event.is_set():
                break

        if self._stop_event.is_set():
            with self._lock:
                self._process_state = TorProcessState.STOPPED
            return

        # Process ownership verification: our spawned process MUST still be alive!
        with self._lock:
            proc_alive = self._process is not None and self._process.poll() is None
            proc_pid = self._process.pid if self._process else None

        if not success or not proc_alive:
            with self._lock:
                self._process_state = TorProcessState.FAILED
                if not self._last_error:
                    self._last_error = "Tor process failed to bootstrap or exited prematurely."
                err_msg = self._last_error
            self.stop()
            if "Port conflict" in err_msg or "bind" in err_msg.lower():
                raise TorPortConflictError(err_msg)
            raise TorBootstrapError(err_msg)

        # Confirm SOCKS listener port is responding
        if not self._probe_socks_listener(self.config.socks_host, target_port, timeout=5.0):
            with self._lock:
                self._process_state = TorProcessState.FAILED
                self._last_error = f"Tor SOCKS listener {self.config.socks_host}:{target_port} not responding after bootstrap."
                err_msg = self._last_error
            self.stop()
            raise TorSupervisorError(err_msg)

        # Verify process ownership of the listening socket
        ownership_verified, owner_pid = self._verify_listener_ownership(
            self.config.socks_host, target_port, proc_pid
        )
        if not ownership_verified:
            with self._lock:
                self._process_state = TorProcessState.FAILED
                self._last_error = (
                    f"Security violation: SOCKS listener {self.config.socks_host}:{target_port} "
                    f"is owned by PID {owner_pid}, not our Tor process (PID {proc_pid})."
                )
            self.stop()
            raise TorPortConflictError(self._last_error)

        with self._lock:
            self._process_state = TorProcessState.SOCKS_READY

    def stop(self) -> None:
        """Gracefully terminates the Tor process and cleans up ephemeral state."""
        with self._lock:
            self._is_stopping = True
            self._stop_event.set()
            if self._ready_event:
                self._ready_event.set()
            proc = self._process
            self._process = None
            self._bootstrapped = False
            self._bootstrap_percent = 0
            self._active_socks_port = None
            self._process_state = TorProcessState.STOPPED

        if proc and proc.poll() is None:
            try:
                if sys.platform == "win32":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3.0)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2.0)
            except Exception:
                pass

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)
            self._monitor_thread = None

        self._cleanup_ephemeral_dir()

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
                "process_state": self._process_state.value,
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
                        self._process_state = TorProcessState.FAILED
                    failure_event.set()

                # Check bootstrap progress
                m = self.BOOTSTRAP_PATTERN.search(line_str)
                if m:
                    percent = int(m.group(1))
                    with self._lock:
                        self._bootstrap_percent = percent
                        if percent < 100 and self._process_state in (
                            TorProcessState.PROCESS_STARTED,
                            TorProcessState.BOOTSTRAPPING,
                        ):
                            self._process_state = TorProcessState.BOOTSTRAPPING
                        elif percent >= 100:
                            self._process_state = TorProcessState.BOOTSTRAPPED_100
                            self._bootstrapped = True

                    if self.on_bootstrap_progress:
                        try:
                            self.on_bootstrap_progress(percent, line_str)
                        except Exception:
                            pass

                    if percent >= 100:
                        ready_event.set()

        except Exception as e:
            with self._lock:
                self._last_error = f"Monitor read error: {e}"
                self._process_state = TorProcessState.FAILED
        finally:
            proc.stdout.close()
            exit_code = proc.wait()

            with self._lock:
                was_stopping = self._is_stopping
                self._bootstrapped = False
                if not was_stopping:
                    if not self._last_error:
                        self._last_error = f"Tor process terminated unexpectedly with exit code {exit_code}"
                    self._process_state = TorProcessState.FAILED

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

    @staticmethod
    def _verify_listener_ownership(host: str, port: int, expected_pid: Optional[int]) -> Tuple[bool, Optional[int]]:
        """
        Verifies that the process listening on host:port matches expected_pid or is a child thereof.
        On Windows, interrogates netstat TCP tables and process tree.
        """
        if not expected_pid:
            return False, None

        if sys.platform == "win32":
            try:
                proc = subprocess.run(
                    ["netstat", "-ano", "-p", "tcp"],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                pattern = re.compile(
                    rf"^\s*TCP\s+(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0):{port}\s+.*?LISTENING\s+(\d+)\s*$",
                    re.IGNORECASE,
                )
                for line in proc.stdout.splitlines():
                    m = pattern.match(line)
                    if m:
                        found_pid = int(m.group(1))
                        if found_pid == expected_pid:
                            return True, found_pid
                        if _is_pid_descendant_win32(found_pid, expected_pid):
                            return True, found_pid
                        return False, found_pid
            except Exception:
                pass

        # Fallback for environments where netstat interrogation is unavailable or non-Windows
        return (True, expected_pid)

    def _cleanup_ephemeral_dir(self) -> None:
        """Safely removes the temporary Tor data directory if one was created."""
        target = self._ephemeral_data_dir
        self._ephemeral_data_dir = None
        if not target or not os.path.exists(target):
            return

        def _handle_readonly(func, path, exc):
            try:
                os.chmod(path, 0o777)
                func(path)
            except Exception:
                pass

        try:
            shutil.rmtree(target, onerror=_handle_readonly)
        except Exception:
            pass
