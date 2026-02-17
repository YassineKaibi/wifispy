from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from collections import deque
import time


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EncryptionType(Enum):
    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    UNKNOWN = "Unknown"


class AssociationStatus(Enum):
    PROBING = auto()
    AUTHENTICATING = auto()
    ASSOCIATED = auto()
    DISCONNECTED = auto()


class AlertSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertType(Enum):
    DEAUTH_FLOOD = "Deauth Flood"
    EVIL_TWIN = "Evil Twin"
    ROGUE_AP = "Rogue AP"
    CLIENT_ANOMALY = "Client Anomaly"
    KARMA_ATTACK = "Karma Attack"


# ---------------------------------------------------------------------------
# Parsed frame types
# ---------------------------------------------------------------------------

@dataclass
class WiFiFrame:
    timestamp: float
    signal_dbm: int | None
    channel: int | None
    source_mac: str | None
    dest_mac: str | None
    bssid: str | None
    frame_length: int
    raw_packet: Any = field(repr=False, default=None)


@dataclass
class BeaconFrame(WiFiFrame):
    ssid: str = ""
    encryption_type: EncryptionType = EncryptionType.UNKNOWN
    beacon_interval: int = 100
    supported_rates: list[float] = field(default_factory=list)


@dataclass
class ProbeRequest(WiFiFrame):
    ssid: str | None = None  # None = broadcast probe
    client_mac: str = ""


@dataclass
class ProbeResponse(WiFiFrame):
    ssid: str = ""
    ap_mac: str = ""


@dataclass
class AuthenticationFrame(WiFiFrame):
    client_mac: str = ""
    ap_mac: str = ""
    algorithm: int = 0
    status_code: int = 0


@dataclass
class AssociationRequest(WiFiFrame):
    client_mac: str = ""
    ap_mac: str = ""
    ssid: str = ""


@dataclass
class AssociationResponse(WiFiFrame):
    client_mac: str = ""
    ap_mac: str = ""
    status_code: int = 0


@dataclass
class DeauthFrame(WiFiFrame):
    sender_mac: str = ""
    target_mac: str = ""
    reason_code: int = 0


@dataclass
class DisassociationFrame(WiFiFrame):
    sender_mac: str = ""
    target_mac: str = ""
    reason_code: int = 0


@dataclass
class EAPOLFrame(WiFiFrame):
    client_mac: str = ""
    ap_mac: str = ""
    key_info: int = 0
    message_number: int = 0  # 1-4
    nonce: bytes = b""
    mic: bytes = b""


@dataclass
class DataFrame(WiFiFrame):
    encrypted: bool = False
    qos: bool = False


@dataclass
class UnknownFrame(WiFiFrame):
    raw_type: int = 0
    raw_subtype: int = 0


# ---------------------------------------------------------------------------
# State objects
# ---------------------------------------------------------------------------

@dataclass
class AccessPointState:
    ssid: str
    bssid: str
    channel: int | None = None
    encryption: EncryptionType = EncryptionType.UNKNOWN
    signal_dbm_history: deque = field(default_factory=lambda: deque(maxlen=10))
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    beacon_count: int = 0
    hidden_ssid: bool = False
    vendor: str = ""

    @property
    def signal_dbm(self) -> int | None:
        if not self.signal_dbm_history:
            return None
        return round(sum(self.signal_dbm_history) / len(self.signal_dbm_history))

    @property
    def client_count(self) -> int:
        # Set externally by the aggregator to avoid circular refs
        return self._client_count if hasattr(self, "_client_count") else 0

    @client_count.setter
    def client_count(self, value: int) -> None:
        self._client_count = value


@dataclass
class ClientState:
    mac: str
    associated_bssid: str | None = None
    signal_dbm: int | None = None
    probe_history: list[str] = field(default_factory=list)
    data_frame_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    vendor: str = ""


@dataclass
class AssociationState:
    bssid: str
    client_mac: str
    status: AssociationStatus = AssociationStatus.PROBING
    last_transition: float = field(default_factory=time.time)
    data_frame_count: int = 0


@dataclass
class HandshakeMessage:
    message_number: int
    timestamp: float
    raw_packet: Any = field(repr=False, default=None)


@dataclass
class HandshakeState:
    bssid: str
    client_mac: str
    messages: dict[int, HandshakeMessage] = field(default_factory=dict)
    complete: bool = False
    attempts: int = 0
    beacon_packet: Any = field(repr=False, default=None)  # for pcap export

    @property
    def captured_messages(self) -> list[int]:
        return sorted(self.messages.keys())

    def is_complete(self) -> bool:
        # All 4, or at minimum 1+2+3
        return {1, 2, 3, 4}.issubset(self.messages) or {1, 2, 3}.issubset(self.messages)

    def add_message(self, msg: HandshakeMessage) -> None:
        if msg.message_number not in self.messages:
            self.messages[msg.message_number] = msg
        self.complete = self.is_complete()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    alert_type: AlertType
    severity: AlertSeverity
    timestamp: float = field(default_factory=time.time)
    description: str = ""
    involved_macs: list[str] = field(default_factory=list)
