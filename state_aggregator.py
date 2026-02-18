from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Callable

from config import Config
from models import (
    WiFiFrame,
    BeaconFrame,
    ProbeRequest,
    ProbeResponse,
    AuthenticationFrame,
    AssociationRequest,
    AssociationResponse,
    DeauthFrame,
    DisassociationFrame,
    EAPOLFrame,
    DataFrame,
    AccessPointState,
    ClientState,
    AssociationState,
    AssociationStatus,
    HandshakeState,
    HandshakeMessage,
    EncryptionType,
)

logger = logging.getLogger(__name__)


class StateAggregator:
    def __init__(self, config: Config, vendor_lookup: Callable[[str], str] | None = None) -> None:
        self.config = config

        # Core registries
        self.aps: dict[str, AccessPointState] = {}
        self.clients: dict[str, ClientState] = {}
        self.associations: dict[tuple[str, str], AssociationState] = {}
        self.handshakes: dict[tuple[str, str], HandshakeState] = {}

        # Vendor lookup function: mac -> vendor name
        self._vendor_lookup = vendor_lookup or (lambda mac: "")

        # Callback when a complete handshake is captured
        self._on_handshake_complete: list[Callable] = []

        # Stats
        self._frame_count = 0
        self._start_time = time.time()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def frame_count(self) -> int:
        return self._frame_count

    @property
    def uptime(self) -> float:
        return time.time() - self._start_time

    def on_handshake_complete(self, callback: Callable) -> None:
        """Register a callback for when a full handshake is captured."""
        self._on_handshake_complete.append(callback)

    async def process_frame(self, frame: WiFiFrame) -> None:
        """Main entry point -- called by the frame parser for each parsed frame."""
        self._frame_count += 1

        if isinstance(frame, BeaconFrame):
            self._handle_beacon(frame)
        elif isinstance(frame, ProbeRequest):
            self._handle_probe_request(frame)
        elif isinstance(frame, ProbeResponse):
            self._handle_probe_response(frame)
        elif isinstance(frame, AuthenticationFrame):
            self._handle_authentication(frame)
        elif isinstance(frame, AssociationRequest):
            self._handle_association_request(frame)
        elif isinstance(frame, AssociationResponse):
            self._handle_association_response(frame)
        elif isinstance(frame, DeauthFrame):
            self._handle_deauth(frame)
        elif isinstance(frame, DisassociationFrame):
            self._handle_disassociation(frame)
        elif isinstance(frame, EAPOLFrame):
            self._handle_eapol(frame)
        elif isinstance(frame, DataFrame):
            self._handle_data(frame)

    def get_ap_client_count(self, bssid: str) -> int:
        """Count clients currently associated with an AP."""
        count = 0
        for (b, _), assoc in self.associations.items():
            if b == bssid and assoc.status == AssociationStatus.ASSOCIATED:
                count += 1
        return count

    def get_clients_for_ap(self, bssid: str) -> list[ClientState]:
        """Get all clients associated with a specific AP."""
        result = []
        for (b, client_mac), assoc in self.associations.items():
            if b == bssid and assoc.status == AssociationStatus.ASSOCIATED:
                if client_mac in self.clients:
                    result.append(self.clients[client_mac])
        return result

    def get_ap_for_client(self, client_mac: str) -> AccessPointState | None:
        """Get the AP a client is currently associated with."""
        client = self.clients.get(client_mac)
        if client and client.associated_bssid:
            return self.aps.get(client.associated_bssid)
        return None

    def get_handshake_progress(self, bssid: str, client_mac: str) -> HandshakeState | None:
        """Get handshake capture progress for a specific AP-client pair."""
        return self.handshakes.get((bssid, client_mac))

    def get_complete_handshakes(self) -> list[HandshakeState]:
        """Get all completed handshakes."""
        return [hs for hs in self.handshakes.values() if hs.complete]

    # ------------------------------------------------------------------
    # Frame handlers
    # ------------------------------------------------------------------

    def _handle_beacon(self, frame: BeaconFrame) -> None:
        bssid = frame.bssid
        if not bssid:
            return

        if bssid in self.aps:
            ap = self.aps[bssid]
            ap.last_seen = frame.timestamp
            ap.beacon_count += 1
            if frame.signal_dbm is not None:
                ap.signal_dbm_history.append(frame.signal_dbm)
            # Update SSID if we got a non-hidden one and current is hidden
            if frame.ssid != "<hidden>" and ap.hidden_ssid:
                ap.ssid = frame.ssid
                ap.hidden_ssid = False
            if frame.channel:
                ap.channel = frame.channel
            if frame.encryption_type != EncryptionType.UNKNOWN:
                ap.encryption = frame.encryption_type
        else:
            ap = AccessPointState(
                ssid=frame.ssid,
                bssid=bssid,
                channel=frame.channel,
                encryption=frame.encryption_type,
                first_seen=frame.timestamp,
                last_seen=frame.timestamp,
                beacon_count=1,
                hidden_ssid=(frame.ssid == "<hidden>"),
                vendor=self._vendor_lookup(bssid),
            )
            if frame.signal_dbm is not None:
                ap.signal_dbm_history.append(frame.signal_dbm)
            self.aps[bssid] = ap
            logger.debug(f"New AP: {ap.ssid} ({bssid}) ch={ap.channel} enc={ap.encryption.value}")

    def _handle_probe_request(self, frame: ProbeRequest) -> None:
        client_mac = frame.client_mac
        if not client_mac:
            return

        client = self._get_or_create_client(client_mac, frame)

        # Record probed SSID
        if frame.ssid and frame.ssid not in client.probe_history:
            client.probe_history.append(frame.ssid)

        # If directed probe (not broadcast), update association state
        if frame.ssid and frame.bssid:
            key = (frame.bssid, client_mac)
            if key not in self.associations:
                self.associations[key] = AssociationState(
                    bssid=frame.bssid,
                    client_mac=client_mac,
                    status=AssociationStatus.PROBING,
                    last_transition=frame.timestamp,
                )

    def _handle_probe_response(self, frame: ProbeResponse) -> None:
        ap_mac = frame.ap_mac
        if not ap_mac:
            return

        # A probe response from a BSSID we've seen as an AP -- update last_seen
        if ap_mac in self.aps:
            self.aps[ap_mac].last_seen = frame.timestamp

        # If the AP was hidden, a directed probe response reveals its SSID
        if ap_mac in self.aps and self.aps[ap_mac].hidden_ssid and frame.ssid:
            self.aps[ap_mac].ssid = frame.ssid
            self.aps[ap_mac].hidden_ssid = False
            logger.debug(f"Hidden SSID revealed: {frame.ssid} for {ap_mac}")

    def _handle_authentication(self, frame: AuthenticationFrame) -> None:
        client_mac = frame.client_mac
        ap_mac = frame.ap_mac
        if not client_mac or not ap_mac:
            return

        self._get_or_create_client(client_mac, frame)

        key = (ap_mac, client_mac)
        if key in self.associations:
            self.associations[key].status = AssociationStatus.AUTHENTICATING
            self.associations[key].last_transition = frame.timestamp
        else:
            self.associations[key] = AssociationState(
                bssid=ap_mac,
                client_mac=client_mac,
                status=AssociationStatus.AUTHENTICATING,
                last_transition=frame.timestamp,
            )

    def _handle_association_request(self, frame: AssociationRequest) -> None:
        client_mac = frame.client_mac
        ap_mac = frame.ap_mac
        if not client_mac or not ap_mac:
            return

        client = self._get_or_create_client(client_mac, frame)
        client.associated_bssid = ap_mac

        key = (ap_mac, client_mac)
        if key in self.associations:
            self.associations[key].status = AssociationStatus.AUTHENTICATING
            self.associations[key].last_transition = frame.timestamp
        else:
            self.associations[key] = AssociationState(
                bssid=ap_mac,
                client_mac=client_mac,
                status=AssociationStatus.AUTHENTICATING,
                last_transition=frame.timestamp,
            )

    def _handle_association_response(self, frame: AssociationResponse) -> None:
        client_mac = frame.client_mac
        ap_mac = frame.ap_mac
        if not client_mac or not ap_mac:
            return

        client = self._get_or_create_client(client_mac, frame)

        key = (ap_mac, client_mac)
        if frame.status_code == 0:  # success
            client.associated_bssid = ap_mac
            if key in self.associations:
                self.associations[key].status = AssociationStatus.ASSOCIATED
                self.associations[key].last_transition = frame.timestamp
            else:
                self.associations[key] = AssociationState(
                    bssid=ap_mac,
                    client_mac=client_mac,
                    status=AssociationStatus.ASSOCIATED,
                    last_transition=frame.timestamp,
                )
            logger.debug(f"Client {client_mac} associated with {ap_mac}")

    def _handle_deauth(self, frame: DeauthFrame) -> None:
        sender = frame.sender_mac
        target = frame.target_mac
        if not sender or not target:
            return

        # Determine which is the AP and which is the client
        # If sender is a known AP, client is the target
        # If target is a known AP, client is the sender
        if sender in self.aps:
            bssid, client_mac = sender, target
        elif target in self.aps:
            bssid, client_mac = target, sender
        else:
            # Neither is a known AP -- use bssid field
            bssid = frame.bssid or sender
            client_mac = target if target != bssid else sender

        key = (bssid, client_mac)
        if key in self.associations:
            self.associations[key].status = AssociationStatus.DISCONNECTED
            self.associations[key].last_transition = frame.timestamp

        if client_mac in self.clients:
            if self.clients[client_mac].associated_bssid == bssid:
                self.clients[client_mac].associated_bssid = None

    def _handle_disassociation(self, frame: DisassociationFrame) -> None:
        # Same logic as deauth
        sender = frame.sender_mac
        target = frame.target_mac
        if not sender or not target:
            return

        if sender in self.aps:
            bssid, client_mac = sender, target
        elif target in self.aps:
            bssid, client_mac = target, sender
        else:
            bssid = frame.bssid or sender
            client_mac = target if target != bssid else sender

        key = (bssid, client_mac)
        if key in self.associations:
            self.associations[key].status = AssociationStatus.DISCONNECTED
            self.associations[key].last_transition = frame.timestamp

        if client_mac in self.clients:
            if self.clients[client_mac].associated_bssid == bssid:
                self.clients[client_mac].associated_bssid = None

    def _handle_eapol(self, frame: EAPOLFrame) -> None:
        bssid = frame.ap_mac
        client_mac = frame.client_mac
        if not bssid or not client_mac:
            return

        self._get_or_create_client(client_mac, frame)

        key = (bssid, client_mac)

        if key not in self.handshakes:
            # Look for a beacon packet for this BSSID
            beacon_pkt = None
            if bssid in self.aps:
                # We'll store the raw_packet from the most recent beacon
                # The pcap exporter needs it for the SSID
                beacon_pkt = None  # populated by pcap exporter separately
            self.handshakes[key] = HandshakeState(
                bssid=bssid,
                client_mac=client_mac,
            )

        hs = self.handshakes[key]
        was_complete = hs.complete

        msg = HandshakeMessage(
            message_number=frame.message_number,
            timestamp=frame.timestamp,
            raw_packet=frame.raw_packet,
        )
        hs.add_message(msg)

        logger.debug(
            f"EAPOL M{frame.message_number} captured: {client_mac} <-> {bssid} "
            f"[{','.join(str(m) for m in hs.captured_messages)}]"
        )

        # Fire callback on first completion
        if hs.complete and not was_complete:
            hs.attempts += 1
            logger.info(
                f"Complete handshake captured: {client_mac} <-> {bssid} "
                f"(attempt #{hs.attempts})"
            )
            for cb in self._on_handshake_complete:
                try:
                    cb(hs)
                except Exception as e:
                    logger.debug(f"Handshake callback error: {e}")

    def _handle_data(self, frame: DataFrame) -> None:
        src = frame.source_mac
        dst = frame.dest_mac
        bssid = frame.bssid
        if not src or not bssid:
            return

        # Determine client MAC -- the one that isn't the BSSID
        if src == bssid:
            client_mac = dst
        elif dst == bssid:
            client_mac = src
        else:
            # ToDS/FromDS both set (WDS) or neither -- skip
            return

        if not client_mac:
            return

        client = self._get_or_create_client(client_mac, frame)
        client.data_frame_count += 1
        client.associated_bssid = bssid

        # Update AP last_seen from data traffic
        if bssid in self.aps:
            self.aps[bssid].last_seen = frame.timestamp

        # Update association
        key = (bssid, client_mac)
        if key in self.associations:
            self.associations[key].data_frame_count += 1
            if self.associations[key].status != AssociationStatus.ASSOCIATED:
                self.associations[key].status = AssociationStatus.ASSOCIATED
                self.associations[key].last_transition = frame.timestamp
        else:
            self.associations[key] = AssociationState(
                bssid=bssid,
                client_mac=client_mac,
                status=AssociationStatus.ASSOCIATED,
                last_transition=frame.timestamp,
                data_frame_count=1,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_or_create_client(self, mac: str, frame: WiFiFrame) -> ClientState:
        """Get existing client or create a new one."""
        if mac in self.clients:
            client = self.clients[mac]
            client.last_seen = frame.timestamp
            if frame.signal_dbm is not None:
                client.signal_dbm = frame.signal_dbm
            return client

        client = ClientState(
            mac=mac,
            signal_dbm=frame.signal_dbm,
            first_seen=frame.timestamp,
            last_seen=frame.timestamp,
            vendor=self._vendor_lookup(mac),
        )
        self.clients[mac] = client
        logger.debug(f"New client: {mac} (vendor: {client.vendor or 'unknown'})")
        return client
