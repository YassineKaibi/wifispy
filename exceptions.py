class WifiSpyError(Exception):
    """Base exception for WifiSpy."""


class AdapterNotFoundError(WifiSpyError):
    """No wireless adapter detected."""


class MonitorModeError(WifiSpyError):
    """Failed to enable/disable monitor mode."""


class ChannelError(WifiSpyError):
    """Failed to set channel."""


class CaptureError(WifiSpyError):
    """Packet capture failed or stopped unexpectedly."""


class ExportError(WifiSpyError):
    """PCAP export failed."""


class InterfaceDisconnectedError(WifiSpyError):
    """USB adapter disconnected during operation."""
