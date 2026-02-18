from __future__ import annotations

import asyncio
import logging
import threading
from typing import Callable

from config import Config
from exceptions import CaptureError

logger = logging.getLogger(__name__)


def _init_scapy():
    """Lazy-load Scapy to avoid import-time crashes in environments without
    full network stack (containers, CI, etc.)."""
    from scapy.all import sniff, conf as scapy_conf
    scapy_conf.verb = 0
    return sniff


class CaptureEngine:
    def __init__(self, config: Config, interface: str) -> None:
        self.config = config
        self.interface = interface
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._packet_count = 0
        self._drop_count = 0
        self._extra_callbacks: list[Callable] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def drop_count(self) -> int:
        return self._drop_count

    @property
    def queue(self) -> asyncio.Queue:
        return self._queue

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Start the sniff thread. Must be called from the async context."""
        if self._thread and self._thread.is_alive():
            logger.warning("Capture engine already running.")
            return
        self._loop = loop
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sniff_worker,
            name="capture-sniff",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"Capture started on '{self.interface}'.")

    def stop(self) -> None:
        """Signal the sniff thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                logger.warning("Sniff thread did not exit cleanly.")
        self._thread = None
        logger.info(
            f"Capture stopped. Packets: {self._packet_count}, Drops: {self._drop_count}"
        )

    async def get_packet(self):
        """Async interface for consumers to pull packets from the queue."""
        return await self._queue.get()

    def register_callback(self, callback: Callable) -> None:
        """Register an additional synchronous callback for each packet.

        Useful for the pcap exporter writing raw packets from the sniff thread
        without async overhead.
        """
        self._extra_callbacks.append(callback)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _sniff_worker(self) -> None:
        """Blocking sniff loop running in a dedicated thread."""
        try:
            sniff_fn = _init_scapy()
            sniff_fn(
                iface=self.interface,
                prn=self._on_packet,
                store=0,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            logger.error(
                "Permission denied. Run with sudo or as root for raw socket access."
            )
            raise CaptureError("Insufficient permissions for packet capture.")
        except OSError as e:
            if self._stop_event.is_set():
                return  # expected during shutdown
            logger.error(f"Capture error: {e}")
            raise CaptureError(f"Sniff failed on '{self.interface}': {e}")
        except Exception as e:
            if self._stop_event.is_set():
                return
            logger.error(f"Unexpected capture error: {e}")
            raise CaptureError(str(e))

    def _on_packet(self, packet) -> None:
        """Called by Scapy for each captured packet. Runs in the sniff thread."""
        self._packet_count += 1

        # Fire synchronous callbacks (e.g., pcap writer)
        for cb in self._extra_callbacks:
            try:
                cb(packet)
            except Exception as e:
                logger.debug(f"Extra callback error: {e}")

        # Push to async queue for the frame parser
        if self._loop is None:
            return
        try:
            self._queue.put_nowait(packet)
        except asyncio.QueueFull:
            self._drop_count += 1
            if self._drop_count % 100 == 1:
                logger.warning(
                    f"Capture queue full, packet dropped (total drops: {self._drop_count})."
                )
