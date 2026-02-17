from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # Interface
    interface: str = "wlan0"
    monitor_interface: str = "wlan0mon"

    # Channel hopping
    channel_hop_interval: float = 0.25
    channels_24ghz: list[int] = field(
        default_factory=lambda: [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
    )
    channels_5ghz: list[int] = field(
        default_factory=lambda: [
            36, 40, 44, 48, 52, 56, 60, 64,
            100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
            149, 153, 157, 161, 165,
        ]
    )
    enable_5ghz: bool = False

    # Signal tracking
    rssi_window_size: int = 10

    # Alert engine
    deauth_threshold: int = 10
    deauth_window: float = 10.0
    alert_buffer_size: int = 100
    ssid_similarity_threshold: float = 0.8  # for rogue AP fuzzy matching

    # PCAP exporter
    pcap_output_dir: Path = field(default_factory=lambda: Path("./captures"))
    pcap_max_size_mb: int = 100
    pcap_max_files: int = 5

    # CLI renderer
    render_interval: float = 1.0
    stale_threshold: float = 60.0

    # Deauth module
    deauth_burst_count: int = 64
    deauth_burst_delay: float = 0.1
    deauth_reason_code: int = 7

    @property
    def active_channels(self) -> list[int]:
        channels = list(self.channels_24ghz)
        if self.enable_5ghz:
            channels.extend(self.channels_5ghz)
        return channels
