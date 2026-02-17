from __future__ import annotations

import asyncio
import logging
import subprocess
import re

from config import Config
from exceptions import (
    AdapterNotFoundError,
    MonitorModeError,
    ChannelError,
    InterfaceDisconnectedError,
)

logger = logging.getLogger(__name__)


class InterfaceManager:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.interface = config.interface
        self.monitor_interface = config.monitor_interface
        self.monitor_mode_active = False
        self._hopping = False
        self._hop_task: asyncio.Task | None = None
        self._current_channel: int | None = None
        self._channel_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_adapter(self) -> None:
        """Check that the wireless adapter exists and supports monitor mode."""
        output = self._run_cmd(["iwconfig"], check=False)
        if self.interface not in output:
            raise AdapterNotFoundError(
                f"Interface '{self.interface}' not found. "
                f"Available interfaces:\n{output}"
            )
        # Check monitor mode support via iw
        phy = self._get_phy()
        if phy:
            info = self._run_cmd(["iw", "phy", phy, "info"], check=False)
            if "monitor" not in info.lower():
                raise AdapterNotFoundError(
                    f"Interface '{self.interface}' does not support monitor mode."
                )
        logger.info(f"Adapter '{self.interface}' validated.")

    def kill_interfering_processes(self) -> None:
        """Stop processes that interfere with monitor mode."""
        self._run_cmd(["airmon-ng", "check", "kill"], check=False)
        logger.info("Interfering processes killed.")

    def enable_monitor_mode(self) -> None:
        """Enable monitor mode on the adapter."""
        if self.monitor_mode_active:
            logger.warning("Monitor mode already active.")
            return
        self.kill_interfering_processes()
        output = self._run_cmd(
            ["airmon-ng", "start", self.interface],
            error_cls=MonitorModeError,
            error_msg=f"Failed to enable monitor mode on '{self.interface}'.",
        )
        # airmon-ng may rename the interface
        self.monitor_interface = self._detect_monitor_interface(output)
        self.monitor_mode_active = True
        logger.info(f"Monitor mode enabled on '{self.monitor_interface}'.")

    def disable_monitor_mode(self) -> None:
        """Disable monitor mode and restore managed mode."""
        if not self.monitor_mode_active:
            return
        self.stop_channel_hop()
        self._run_cmd(
            ["airmon-ng", "stop", self.monitor_interface],
            error_cls=MonitorModeError,
            error_msg=f"Failed to disable monitor mode on '{self.monitor_interface}'.",
        )
        self.monitor_mode_active = False
        logger.info(f"Monitor mode disabled. Restored '{self.interface}'.")

    def set_channel(self, channel: int) -> None:
        """Lock the adapter to a specific channel."""
        self._validate_interface_up()
        self._run_cmd(
            ["iwconfig", self.monitor_interface, "channel", str(channel)],
            error_cls=ChannelError,
            error_msg=f"Failed to set channel {channel}.",
        )
        self._current_channel = channel
        logger.debug(f"Channel set to {channel}.")

    @property
    def current_channel(self) -> int | None:
        return self._current_channel

    @property
    def is_hopping(self) -> bool:
        return self._hopping

    async def start_channel_hop(self) -> None:
        """Start cycling through channels in a background task."""
        if self._hopping:
            return
        self._hopping = True
        self._hop_task = asyncio.create_task(self._hop_loop())
        logger.info("Channel hopping started.")

    def stop_channel_hop(self) -> None:
        """Stop channel hopping."""
        self._hopping = False
        if self._hop_task and not self._hop_task.done():
            self._hop_task.cancel()
            self._hop_task = None
        logger.info("Channel hopping stopped.")

    async def lock_channel(self, channel: int) -> None:
        """Stop hopping and lock to a specific channel."""
        self.stop_channel_hop()
        async with self._channel_lock:
            self.set_channel(channel)
        logger.info(f"Channel locked to {channel}.")

    async def resume_hop(self) -> None:
        """Resume channel hopping after a lock."""
        await self.start_channel_hop()

    def cleanup(self) -> None:
        """Restore adapter state on shutdown."""
        self.stop_channel_hop()
        try:
            self.disable_monitor_mode()
        except MonitorModeError:
            logger.error("Failed to cleanly disable monitor mode during shutdown.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _hop_loop(self) -> None:
        """Cycle through configured channels."""
        channels = self.config.active_channels
        idx = 0
        while self._hopping:
            channel = channels[idx % len(channels)]
            try:
                async with self._channel_lock:
                    self.set_channel(channel)
            except ChannelError:
                logger.warning(f"Failed to hop to channel {channel}, skipping.")
            except InterfaceDisconnectedError:
                logger.error("Adapter disconnected during channel hop.")
                self._hopping = False
                raise
            idx += 1
            await asyncio.sleep(self.config.channel_hop_interval)

    def _get_phy(self) -> str | None:
        """Get the phy name for the interface (e.g., phy0)."""
        try:
            output = self._run_cmd(
                ["iw", "dev", self.interface, "info"], check=False
            )
            match = re.search(r"wiphy\s+(\d+)", output)
            if match:
                return f"phy{match.group(1)}"
        except Exception:
            pass
        return None

    def _detect_monitor_interface(self, airmon_output: str) -> str:
        """Parse airmon-ng output to find the monitor interface name."""
        # airmon-ng may output the new interface name in various formats
        # Try common patterns
        patterns = [
            rf"\(monitor mode.*enabled on (\S+)\)",
            rf"\(monitor mode.*enabled\).*?(\S+mon\b)",
            rf"(\S*mon)\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, airmon_output)
            if match:
                return match.group(1).rstrip(")")
        # Fallback: check if expected monitor interface exists
        output = self._run_cmd(["iwconfig"], check=False)
        if self.monitor_interface in output:
            return self.monitor_interface
        # Last resort: interface name + "mon"
        fallback = f"{self.interface}mon"
        if fallback in output:
            return fallback
        return self.monitor_interface

    def _validate_interface_up(self) -> None:
        """Verify the monitor interface still exists."""
        output = self._run_cmd(["iwconfig"], check=False)
        if self.monitor_interface not in output:
            self.monitor_mode_active = False
            raise InterfaceDisconnectedError(
                f"Monitor interface '{self.monitor_interface}' not found. "
                "Adapter may have been disconnected."
            )

    def _run_cmd(
        self,
        cmd: list[str],
        check: bool = True,
        error_cls: type[Exception] | None = None,
        error_msg: str = "",
    ) -> str:
        """Run a shell command and return stdout."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if check and result.returncode != 0:
                full_msg = f"{error_msg}\n{result.stderr.strip()}"
                raise (error_cls or RuntimeError)(full_msg)
            return result.stdout + result.stderr
        except FileNotFoundError:
            raise (error_cls or RuntimeError)(
                f"Command not found: {cmd[0]}. Is it installed?"
            )
        except subprocess.TimeoutExpired:
            raise InterfaceDisconnectedError(
                f"Command timed out: {' '.join(cmd)}. Adapter may be unresponsive."
            )
