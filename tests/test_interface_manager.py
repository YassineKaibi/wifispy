import asyncio
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from config import Config
from interface_manager import InterfaceManager
from exceptions import (
    AdapterNotFoundError,
    MonitorModeError,
    ChannelError,
    InterfaceDisconnectedError,
)


@pytest.fixture
def config():
    return Config()


@pytest.fixture
def manager(config):
    return InterfaceManager(config)


def mock_run(stdout="", stderr="", returncode=0):
    """Helper to create a mock subprocess.run result."""
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


# ------------------------------------------------------------------
# validate_adapter
# ------------------------------------------------------------------

class TestValidateAdapter:
    @patch("interface_manager.subprocess.run")
    def test_adapter_found(self, mock_subprocess, manager):
        mock_subprocess.side_effect = [
            # iwconfig
            mock_run(stdout="wlan0     IEEE 802.11  Mode:Managed"),
            # iw dev wlan0 info
            mock_run(stdout="wiphy 0"),
            # iw phy phy0 info
            mock_run(stdout="* monitor"),
        ]
        manager.validate_adapter()  # should not raise

    @patch("interface_manager.subprocess.run")
    def test_adapter_not_found(self, mock_subprocess, manager):
        mock_subprocess.return_value = mock_run(
            stdout="lo        no wireless extensions.\neth0      no wireless extensions."
        )
        with pytest.raises(AdapterNotFoundError, match="not found"):
            manager.validate_adapter()

    @patch("interface_manager.subprocess.run")
    def test_no_monitor_support(self, mock_subprocess, manager):
        mock_subprocess.side_effect = [
            mock_run(stdout="wlan0     IEEE 802.11  Mode:Managed"),
            mock_run(stdout="wiphy 0"),
            mock_run(stdout="* managed\n* AP"),  # no monitor
        ]
        with pytest.raises(AdapterNotFoundError, match="does not support monitor"):
            manager.validate_adapter()


# ------------------------------------------------------------------
# enable_monitor_mode
# ------------------------------------------------------------------

class TestEnableMonitorMode:
    @patch("interface_manager.subprocess.run")
    def test_enable_success(self, mock_subprocess, manager):
        mock_subprocess.side_effect = [
            # check kill
            mock_run(stdout="Killing processes..."),
            # airmon-ng start
            mock_run(stdout="(monitor mode enabled on wlan0mon)"),
        ]
        manager.enable_monitor_mode()
        assert manager.monitor_mode_active is True
        assert manager.monitor_interface == "wlan0mon"

    @patch("interface_manager.subprocess.run")
    def test_enable_detects_renamed_interface(self, mock_subprocess, manager):
        mock_subprocess.side_effect = [
            mock_run(),
            mock_run(stdout="(monitor mode enabled on mon0)"),
        ]
        manager.enable_monitor_mode()
        assert manager.monitor_interface == "mon0"

    @patch("interface_manager.subprocess.run")
    def test_enable_fallback_detection(self, mock_subprocess, manager):
        mock_subprocess.side_effect = [
            mock_run(),
            # airmon-ng output doesn't match patterns
            mock_run(stdout="some unrecognized output"),
            # iwconfig fallback
            mock_run(stdout="wlan0mon  IEEE 802.11  Mode:Monitor"),
        ]
        manager.enable_monitor_mode()
        assert manager.monitor_interface == "wlan0mon"

    @patch("interface_manager.subprocess.run")
    def test_enable_failure(self, mock_subprocess, manager):
        mock_subprocess.side_effect = [
            mock_run(),  # check kill
            mock_run(returncode=1, stderr="Error enabling monitor mode"),
        ]
        with pytest.raises(MonitorModeError):
            manager.enable_monitor_mode()
        assert manager.monitor_mode_active is False

    @patch("interface_manager.subprocess.run")
    def test_double_enable_ignored(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        manager.enable_monitor_mode()
        mock_subprocess.assert_not_called()


# ------------------------------------------------------------------
# disable_monitor_mode
# ------------------------------------------------------------------

class TestDisableMonitorMode:
    @patch("interface_manager.subprocess.run")
    def test_disable_success(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.return_value = mock_run()
        manager.disable_monitor_mode()
        assert manager.monitor_mode_active is False

    @patch("interface_manager.subprocess.run")
    def test_disable_when_not_active(self, mock_subprocess, manager):
        manager.disable_monitor_mode()
        mock_subprocess.assert_not_called()

    @patch("interface_manager.subprocess.run")
    def test_disable_failure(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.return_value = mock_run(
            returncode=1, stderr="stop failed"
        )
        with pytest.raises(MonitorModeError):
            manager.disable_monitor_mode()


# ------------------------------------------------------------------
# set_channel
# ------------------------------------------------------------------

class TestSetChannel:
    @patch("interface_manager.subprocess.run")
    def test_set_channel_success(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.side_effect = [
            # _validate_interface_up -> iwconfig
            mock_run(stdout="wlan0mon  IEEE 802.11  Mode:Monitor"),
            # iwconfig channel set
            mock_run(),
        ]
        manager.set_channel(6)
        assert manager.current_channel == 6

    @patch("interface_manager.subprocess.run")
    def test_set_channel_adapter_gone(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.return_value = mock_run(
            stdout="lo        no wireless extensions."
        )
        with pytest.raises(InterfaceDisconnectedError):
            manager.set_channel(6)

    @patch("interface_manager.subprocess.run")
    def test_set_channel_failure(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.side_effect = [
            mock_run(stdout="wlan0mon  IEEE 802.11  Mode:Monitor"),
            mock_run(returncode=1, stderr="SET failed"),
        ]
        with pytest.raises(ChannelError):
            manager.set_channel(99)


# ------------------------------------------------------------------
# channel hopping
# ------------------------------------------------------------------

class TestChannelHopping:
    @patch("interface_manager.subprocess.run")
    def test_hop_cycles_channels(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        channels_set = []

        def capture_channel(*args, **kwargs):
            cmd = args[0]
            if cmd[0] == "iwconfig" and "channel" in cmd:
                channels_set.append(int(cmd[3]))
            # Always return valid monitor interface for validation
            return mock_run(stdout="wlan0mon  IEEE 802.11  Mode:Monitor")

        mock_subprocess.side_effect = capture_channel

        async def run():
            await manager.start_channel_hop()
            await asyncio.sleep(0.8)  # enough for ~3 hops at 0.25s
            manager.stop_channel_hop()

        asyncio.run(run())
        assert len(channels_set) >= 2
        # First channels should be 1, 6, 11 (priority order)
        assert channels_set[0] == 1

    def test_stop_when_not_hopping(self, manager):
        manager.stop_channel_hop()  # should not raise

    @patch("interface_manager.subprocess.run")
    def test_lock_channel_stops_hopping(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.return_value = mock_run(
            stdout="wlan0mon  IEEE 802.11  Mode:Monitor"
        )

        async def run():
            await manager.start_channel_hop()
            assert manager.is_hopping is True
            await manager.lock_channel(11)
            assert manager.is_hopping is False
            assert manager.current_channel == 11

        asyncio.run(run())

    @patch("interface_manager.subprocess.run")
    def test_resume_hop_after_lock(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.return_value = mock_run(
            stdout="wlan0mon  IEEE 802.11  Mode:Monitor"
        )

        async def run():
            await manager.lock_channel(6)
            assert manager.is_hopping is False
            await manager.resume_hop()
            assert manager.is_hopping is True
            manager.stop_channel_hop()

        asyncio.run(run())


# ------------------------------------------------------------------
# cleanup
# ------------------------------------------------------------------

class TestCleanup:
    @patch("interface_manager.subprocess.run")
    def test_cleanup_restores_adapter(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.return_value = mock_run()
        manager.cleanup()
        assert manager.monitor_mode_active is False

    @patch("interface_manager.subprocess.run")
    def test_cleanup_handles_failure(self, mock_subprocess, manager):
        manager.monitor_mode_active = True
        mock_subprocess.return_value = mock_run(
            returncode=1, stderr="failed"
        )
        # should not raise
        manager.cleanup()


# ------------------------------------------------------------------
# _run_cmd edge cases
# ------------------------------------------------------------------

class TestRunCmd:
    @patch("interface_manager.subprocess.run")
    def test_command_not_found(self, mock_subprocess, manager):
        mock_subprocess.side_effect = FileNotFoundError()
        with pytest.raises(RuntimeError, match="not found"):
            manager._run_cmd(["nonexistent"])

    @patch("interface_manager.subprocess.run")
    def test_command_timeout(self, mock_subprocess, manager):
        mock_subprocess.side_effect = subprocess.TimeoutExpired(
            cmd="test", timeout=10
        )
        with pytest.raises(InterfaceDisconnectedError, match="timed out"):
            manager._run_cmd(["test"])
