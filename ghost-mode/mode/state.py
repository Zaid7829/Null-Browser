"""
Ghost Mode Lifecycle State Machine.
Defines explicit Ghost states and transitions:
  DISABLED -> STARTING -> TOR_BOOTSTRAPPING -> READY -> STOPPING -> DISABLED

Guarantees thread-safe transitions, listener notifications, and clean fallback
to DISABLED upon error or unexpected termination.
"""

from enum import Enum
import threading
from typing import Callable, List, Optional


class GhostState(str, Enum):
    DISABLED = "DISABLED"
    STARTING = "STARTING"
    TOR_BOOTSTRAPPING = "TOR_BOOTSTRAPPING"
    READY = "READY"
    STOPPING = "STOPPING"


class StateTransitionError(Exception):
    """Raised when an invalid state transition is attempted."""
    pass


# Strict allowed transitions mapping
VALID_TRANSITIONS = {
    GhostState.DISABLED: {GhostState.STARTING},
    GhostState.STARTING: {GhostState.TOR_BOOTSTRAPPING, GhostState.DISABLED},
    GhostState.TOR_BOOTSTRAPPING: {GhostState.READY, GhostState.STOPPING, GhostState.DISABLED},
    GhostState.READY: {GhostState.STOPPING, GhostState.DISABLED},
    GhostState.STOPPING: {GhostState.DISABLED},
}


class GhostLifecycleStateMachine:
    """Thread-safe state machine managing Ghost Mode lifecycle."""

    def __init__(self, initial_state: GhostState = GhostState.DISABLED):
        self._lock = threading.RLock()
        self._current_state = initial_state
        self._last_error: Optional[str] = None
        self._listeners: List[Callable[[GhostState, GhostState], None]] = []

    @property
    def current_state(self) -> GhostState:
        with self._lock:
            return self._current_state

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self._current_state in (
                GhostState.STARTING,
                GhostState.TOR_BOOTSTRAPPING,
                GhostState.READY,
            )

    @property
    def is_ready(self) -> bool:
        with self._lock:
            return self._current_state == GhostState.READY

    @property
    def last_error(self) -> Optional[str]:
        with self._lock:
            return self._last_error

    def add_listener(self, listener: Callable[[GhostState, GhostState], None]) -> None:
        """Register a callback for state changes: listener(old_state, new_state)."""
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def remove_listener(self, listener: Callable[[GhostState, GhostState], None]) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def transition_to(self, new_state: GhostState, error_message: Optional[str] = None) -> GhostState:
        """
        Transition to a new state if valid.
        Raises StateTransitionError if the transition is disallowed.
        """
        callbacks_to_fire = []
        with self._lock:
            old_state = self._current_state
            if new_state == old_state:
                return old_state

            allowed = VALID_TRANSITIONS.get(old_state, set())
            if new_state not in allowed:
                raise StateTransitionError(
                    f"Invalid Ghost Mode transition: {old_state.value} -> {new_state.value}. "
                    f"Allowed transitions: {[s.value for s in allowed]}"
                )

            self._current_state = new_state
            if error_message:
                self._last_error = error_message
            elif new_state == GhostState.READY:
                self._last_error = None

            callbacks_to_fire = list(self._listeners)

        # Notify listeners outside the lock
        for cb in callbacks_to_fire:
            try:
                cb(old_state, new_state)
            except Exception:
                # Listeners must never break the state machine
                pass

        return self._current_state

    def force_reset(self, reason: Optional[str] = None) -> None:
        """
        Emergency reset to DISABLED state upon unexpected failure or process termination.
        Always allowed regardless of current state.
        """
        callbacks_to_fire = []
        with self._lock:
            old_state = self._current_state
            self._current_state = GhostState.DISABLED
            if reason:
                self._last_error = reason
            callbacks_to_fire = list(self._listeners)

        if old_state != GhostState.DISABLED:
            for cb in callbacks_to_fire:
                try:
                    cb(old_state, GhostState.DISABLED)
                except Exception:
                    pass
