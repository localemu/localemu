"""Per-pipe poller worker mirroring :class:`EsmWorker`.

One thread per pipe — the polling loop calls
:meth:`Poller.poll_events` (already implements long-polling, batching,
filter evaluation and partial-batch-failure handling), and the
processor wired into the poller drives the enrichment + transform +
target dispatch chain. A LocalEmu shutdown signals every worker via
:class:`threading.Event`; the long-poll terminates when the gateway
socket closes.

The state machine matches the AWS public ``PipeState`` enum so a
``DescribePipe`` call reflects the live worker status faithfully.
"""

from __future__ import annotations

import logging
import threading

from localemu.aws.api.pipes import PipeState
from localemu.config import (
    LAMBDA_EVENT_SOURCE_MAPPING_MAX_BACKOFF_ON_EMPTY_POLL_SEC,
    LAMBDA_EVENT_SOURCE_MAPPING_MAX_BACKOFF_ON_ERROR_SEC,
    LAMBDA_EVENT_SOURCE_MAPPING_POLL_INTERVAL_SEC,
)
from localemu.services.lambda_.event_source_mapping.pollers.poller import (
    EmptyPollResultsException,
    Poller,
)
from localemu.utils.backoff import ExponentialBackoff
from localemu.utils.threads import FuncThread

LOG = logging.getLogger(__name__)


class PipeWorker:
    """Runtime side of a Pipe: owns the poller thread + state machine."""

    pipe_arn: str
    pipe_name: str
    account_id: str
    region: str
    poller: Poller
    current_state: PipeState

    _state_lock: threading.RLock
    _shutdown_event: threading.Event
    _poller_thread: FuncThread | None

    def __init__(
        self,
        *,
        pipe_arn: str,
        pipe_name: str,
        account_id: str,
        region: str,
        poller: Poller,
        desired_running: bool = True,
    ) -> None:
        self.pipe_arn = pipe_arn
        self.pipe_name = pipe_name
        self.account_id = account_id
        self.region = region
        self.poller = poller
        self.desired_running = desired_running
        self.current_state = PipeState.CREATING
        self._state_lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._poller_thread = None
        self._graceful_shutdown_triggered = False

    # ------------------------------------------------------------------
    # Lifecycle API
    # ------------------------------------------------------------------
    def create(self) -> None:
        """Initial registration. Starts the poller iff DesiredState=RUNNING.

        STOPPED-on-create pipes register with :class:`PipeManager` but do
        not poll until a subsequent ``StartPipe`` arrives.
        """
        if self.desired_running:
            self.start()
            return
        with self._state_lock:
            self.current_state = PipeState.STOPPED
            self._sync_state_to_moto()

    def start(self) -> None:
        """Idempotent start — kicks off the poller thread if not running."""
        with self._state_lock:
            if self._poller_thread is not None and self._poller_thread.is_alive():
                return
            if self.current_state != PipeState.CREATING:
                self.current_state = PipeState.STARTING
                self._sync_state_to_moto()
            self.desired_running = True
        self._shutdown_event.clear()
        self._poller_thread = FuncThread(
            self._poller_loop, name=f"pipe-{self.pipe_name}-poller",
        )
        self._poller_thread.start()

    def stop(self) -> None:
        """Signal shutdown — the poller thread exits on its next wakeup
        and the close() hook closes any long-lived source clients."""
        with self._state_lock:
            self.desired_running = False
            if self.current_state in (PipeState.STOPPED, PipeState.DELETING):
                return
            self.current_state = PipeState.STOPPING
            self._sync_state_to_moto()
        self._shutdown_event.set()
        thread = self._poller_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
        with self._state_lock:
            self.current_state = PipeState.STOPPED
            self._sync_state_to_moto()

    def delete(self) -> None:
        """Drain the poller then transition out of the registry. Caller
        (``PipeManager.remove``) is responsible for the dictionary
        eviction; this method's job is to stop polling."""
        with self._state_lock:
            self.current_state = PipeState.DELETING
            self._sync_state_to_moto()
        self._shutdown_event.set()
        thread = self._poller_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _poller_loop(self, *args, **kwargs) -> None:
        # ``FuncThread.run`` passes a positional ``params`` arg; accept
        # *args/**kwargs so the unused param doesn't crash the loop on
        # start (the ESM worker uses the same signature for the same
        # reason).
        with self._state_lock:
            self.current_state = PipeState.RUNNING
            self._sync_state_to_moto()
        error_boff = ExponentialBackoff(
            initial_interval=2,
            max_interval=LAMBDA_EVENT_SOURCE_MAPPING_MAX_BACKOFF_ON_ERROR_SEC,
        )
        empty_boff = ExponentialBackoff(
            initial_interval=1,
            max_interval=LAMBDA_EVENT_SOURCE_MAPPING_MAX_BACKOFF_ON_EMPTY_POLL_SEC,
        )
        interval = LAMBDA_EVENT_SOURCE_MAPPING_POLL_INTERVAL_SEC
        while not self._shutdown_event.is_set():
            try:
                self.poller.poll_events()
                error_boff.reset()
                empty_boff.reset()
                interval = LAMBDA_EVENT_SOURCE_MAPPING_POLL_INTERVAL_SEC
            except EmptyPollResultsException:
                interval = empty_boff.next_backoff()
            except Exception:
                LOG.warning(
                    "Pipe %s poll iteration failed", self.pipe_arn, exc_info=True,
                )
                interval = error_boff.next_backoff()
            finally:
                self._shutdown_event.wait(interval)
        try:
            self.poller.close()
        except Exception:
            LOG.debug("Pipe %s poller close raised", self.pipe_arn, exc_info=True)

    def _sync_state_to_moto(self) -> None:
        """Mirror the worker's state into moto's Pipe model so
        ``DescribePipe`` returns the truthful live state. moto's Pipe
        object stores the current state as ``current_state`` — set
        defensively so a missing backend doesn't break the worker."""
        try:
            from moto.pipes.models import pipes_backends

            backend = pipes_backends[self.account_id][self.region]
            pipe = backend.pipes.get(self.pipe_name)
            if pipe is not None:
                pipe.current_state = self.current_state.value
        except Exception:
            LOG.debug(
                "Pipe %s could not sync state %s to moto",
                self.pipe_arn, self.current_state, exc_info=True,
            )
