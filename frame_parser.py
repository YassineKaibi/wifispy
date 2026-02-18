from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable

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
    UnknownFrame,
    EncryptionType,
)

logger = logging.getLogger(__name__)

# 802.11 frame type constants
_TYPE_MANAGEMENT = 0
_TYPE_CONTROL = 1
_TYPE_DATA = 2

# 802.11 management frame subtype constants
_SUBTYPE_ASSOC_REQ = 0
_SUBTYPE_ASSOC_RESP = 1
_SUBTYPE_PROBE_REQ = 4
_SUBTYPE_PROBE_RESP = 5
_SUBTYPE_BEACON = 8
_SUBTYPE_DISASSOC = 10
_SUBTYPE_AUTH = 11
_SUBTYPE_DEAUTH = 12


class FrameParser:
    def __init__(self) -> None:
        self._parse_count = 0
        self._error_count = 0
        self._consumers: list[Callable] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def parse_count(self) -> int:
        return self._parse_count

    @property
    def error_count(self) -> int:
        return self._error_count

    def add_consumer(self, callback: Callable) -> None:
        """Register an async callback that receives each parsed frame.

        Used by the state aggregator, alert engine, etc.
        """
        self._consumers.append(callback)

    async def run(self, queue: asyncio.Queue) -> None:
        """Main loop: pull raw packets from the capture queue, parse, and fan out."""
        while True:
            packet = await queue.get()
            frame = self.parse(packet)
            if frame is not None:
                for consumer in self._consumers:
                    try:
                        await consumer(frame)
                    except Exception as e:
                        logger.debug(f"Consumer error: {e}")

    def parse(self, packet) -> WiFiFrame | None:
        """Parse a raw Scapy packet into a typed dataclass.

        Returns None if the packet has no 802.11 layer or is malformed.
        """
        try:
            return self._parse_inner(packet)
        except Exception as e:
            self._error_count += 1
            if self._error_count % 100 == 1:
                logger.warning(f"Parse error (total: {self._error_count}): {e}")
            return None

    # ------------------------------------------------------------------
    # Private parsing
    # ------------------------------------------------------------------

    def _parse_inner(self, packet) -> WiFiFrame | None:
        # Lazy import to avoid import-time Scapy crash
        from scapy.layers.dot11 import (
            Dot11,
            Dot11Beacon,
            Dot11ProbeReq,
            Dot11ProbeResp,
            Dot11Auth,
            Dot11AssoReq,
            Dot11AssoResp,
            Dot11Deauth,
            Dot11Disas,
            Dot11Elt,
            RadioTap,
        )
        from scapy.layers.eap import EAPOL

        if not packet.haslayer(Dot11):
            return None

        self._parse_count += 1
        dot11 = packet[Dot11]

        # Extract common fields from Dot11 and RadioTap headers
        base = self._extract_base(packet, dot11)

        frame_type = dot11.type
        frame_subtype = dot11.subtype

        # ----- Management frames -----
        if frame_type == _TYPE_MANAGEMENT:

            if frame_subtype == _SUBTYPE_BEACON:
                return self._parse_beacon(packet, base)

            if frame_subtype == _SUBTYPE_PROBE_REQ:
                ssid = self._extract_ssid(packet)
                return ProbeRequest(
                    **base,
                    ssid=ssid if ssid else None,
                    client_mac=dot11.addr2 or "",
                )

            if frame_subtype == _SUBTYPE_PROBE_RESP:
                return ProbeResponse(
                    **base,
                    ssid=self._extract_ssid(packet) or "",
                    ap_mac=dot11.addr2 or "",
                )

            if frame_subtype == _SUBTYPE_AUTH:
                if packet.haslayer(Dot11Auth):
                    auth = packet[Dot11Auth]
                    return AuthenticationFrame(
                        **base,
                        client_mac=dot11.addr1 or "",
                        ap_mac=dot11.addr2 or "",
                        algorithm=auth.algo,
                        status_code=auth.status,
                    )

            if frame_subtype == _SUBTYPE_ASSOC_REQ:
                return AssociationRequest(
                    **base,
                    client_mac=dot11.addr2 or "",
                    ap_mac=dot11.addr1 or "",
                    ssid=self._extract_ssid(packet) or "",
                )

            if frame_subtype == _SUBTYPE_ASSOC_RESP:
                if packet.haslayer(Dot11AssoResp):
                    resp = packet[Dot11AssoResp]
                    return AssociationResponse(
                        **base,
                        client_mac=dot11.addr1 or "",
                        ap_mac=dot11.addr2 or "",
                        status_code=resp.status,
                    )

            if frame_subtype == _SUBTYPE_DEAUTH:
                if packet.haslayer(Dot11Deauth):
                    deauth = packet[Dot11Deauth]
                    return DeauthFrame(
                        **base,
                        sender_mac=dot11.addr2 or "",
                        target_mac=dot11.addr1 or "",
                        reason_code=deauth.reason,
                    )

            if frame_subtype == _SUBTYPE_DISASSOC:
                if packet.haslayer(Dot11Disas):
                    disas = packet[Dot11Disas]
                    return DisassociationFrame(
                        **base,
                        sender_mac=dot11.addr2 or "",
                        target_mac=dot11.addr1 or "",
                        reason_code=disas.reason,
                    )

            # Unhandled management subtype
            return UnknownFrame(**base, raw_type=frame_type, raw_subtype=frame_subtype)

        # ----- Data frames -----
        if frame_type == _TYPE_DATA:
            # Check for EAPOL (WPA handshake) inside data frames
            if packet.haslayer(EAPOL):
                return self._parse_eapol(packet, dot11, base)

            return DataFrame(
                **base,
                encrypted=bool(dot11.FCfield & 0x40),  # Protected bit
                qos=frame_subtype == 8,  # QoS data subtype
            )

        # ----- Control frames and everything else -----
        return UnknownFrame(**base, raw_type=frame_type, raw_subtype=frame_subtype)

    def _extract_base(self, packet, dot11) -> dict:
        """Extract fields common to all frame types."""
        from scapy.layers.dot11 import RadioTap

        signal_dbm = None
        channel = None
        if packet.haslayer(RadioTap):
            rt = packet[RadioTap]
            signal_dbm = getattr(rt, "dBm_AntSignal", None)
            # RadioTap channel frequency -> channel number
            freq = getattr(rt, "ChannelFrequency", None)
            if freq:
                channel = self._freq_to_channel(freq)

        return dict(
            timestamp=time.time(),
            signal_dbm=signal_dbm,
            channel=channel,
            source_mac=dot11.addr2,
            dest_mac=dot11.addr1,
            bssid=dot11.addr3,
            frame_length=len(packet),
            raw_packet=packet,
        )

    def _extract_ssid(self, packet) -> str:
        """Pull the SSID from the Dot11Elt information elements."""
        from scapy.layers.dot11 import Dot11Elt

        elt = packet.getlayer(Dot11Elt, ID=0)
        if elt and elt.info:
            try:
                return elt.info.decode("utf-8", errors="replace")
            except Exception:
                return ""
        return ""

    def _parse_beacon(self, packet, base: dict) -> BeaconFrame:
        """Parse a beacon frame, extracting SSID and encryption type."""
        ssid = self._extract_ssid(packet)
        encryption = self._detect_encryption(packet)
        hidden = ssid == "" or all(c == "\x00" for c in ssid)

        return BeaconFrame(
            **base,
            ssid=ssid if not hidden else "<hidden>",
            encryption_type=encryption,
        )

    def _detect_encryption(self, packet) -> EncryptionType:
        """Determine encryption type from capability flags and information elements."""
        from scapy.layers.dot11 import Dot11Beacon, Dot11Elt

        # Check capability privacy bit
        if packet.haslayer(Dot11Beacon):
            cap = packet[Dot11Beacon].cap
            if not cap.privacy:
                return EncryptionType.OPEN

        # Walk information elements looking for RSN (WPA2/WPA3) and WPA vendor IE
        has_rsn = False
        has_wpa = False
        rsn_akm_suites = []

        elt = packet.getlayer(Dot11Elt)
        while elt:
            # RSN Information Element (ID 48) = WPA2 or WPA3
            if elt.ID == 48:
                has_rsn = True
                # Parse AKM suite bytes to distinguish WPA2 from WPA3
                # AKM suite type 8 = SAE (WPA3-Personal)
                try:
                    info = bytes(elt.info)
                    # RSN IE structure: version(2) + group cipher(4) +
                    # pairwise count(2) + pairwise suites(4*n) +
                    # akm count(2) + akm suites(4*n)
                    if len(info) >= 8:
                        pairwise_count = int.from_bytes(info[4:6], "little")
                        akm_offset = 6 + (pairwise_count * 4)
                        if len(info) >= akm_offset + 2:
                            akm_count = int.from_bytes(
                                info[akm_offset : akm_offset + 2], "little"
                            )
                            for i in range(akm_count):
                                suite_offset = akm_offset + 2 + (i * 4)
                                if len(info) >= suite_offset + 4:
                                    suite_type = info[suite_offset + 3]
                                    rsn_akm_suites.append(suite_type)
                except Exception:
                    pass

            # Vendor-specific IE (ID 221) with Microsoft WPA OUI
            if elt.ID == 221:
                try:
                    oui = bytes(elt.info[:3])
                    if oui == b"\x00\x50\xf2":  # Microsoft OUI
                        oui_type = elt.info[3]
                        if oui_type == 1:  # WPA
                            has_wpa = True
                except Exception:
                    pass

            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        # Determine encryption type from parsed IEs
        if has_rsn:
            # AKM type 8 = SAE (WPA3-Personal), type 18 = OWE (WPA3-Enhanced Open)
            if 8 in rsn_akm_suites or 18 in rsn_akm_suites:
                return EncryptionType.WPA3
            return EncryptionType.WPA2

        if has_wpa:
            return EncryptionType.WPA

        # Privacy bit set but no RSN/WPA IE = WEP
        return EncryptionType.WEP

    def _parse_eapol(self, packet, dot11, base: dict) -> EAPOLFrame:
        """Parse an EAPOL frame and determine the handshake message number (1-4)."""
        from scapy.layers.eap import EAPOL

        eapol = packet[EAPOL]
        raw_payload = bytes(eapol.payload) if eapol.payload else b""

        # EAPOL-Key frame structure after the EAPOL header:
        # key_info is at bytes 1-2 (big-endian uint16)
        # nonce is at bytes 13-45 (32 bytes)
        # mic is at bytes 77-93 (16 bytes for WPA2)
        key_info = 0
        nonce = b""
        mic = b""

        if len(raw_payload) >= 3:
            key_info = int.from_bytes(raw_payload[1:3], "big")
        if len(raw_payload) >= 45:
            nonce = raw_payload[13:45]
        if len(raw_payload) >= 93:
            mic = raw_payload[77:93]

        msg_num = self._determine_eapol_message(key_info, nonce, mic)

        # Determine client vs AP MAC based on message direction
        # Messages 1 and 3: AP -> Client (addr1=client, addr2=AP)
        # Messages 2 and 4: Client -> AP (addr1=AP, addr2=client)
        if msg_num in (1, 3):
            client_mac = dot11.addr1 or ""
            ap_mac = dot11.addr2 or ""
        else:
            client_mac = dot11.addr2 or ""
            ap_mac = dot11.addr1 or ""

        return EAPOLFrame(
            **base,
            client_mac=client_mac,
            ap_mac=ap_mac,
            key_info=key_info,
            message_number=msg_num,
            nonce=nonce,
            mic=mic,
        )

    def _determine_eapol_message(
        self, key_info: int, nonce: bytes, mic: bytes
    ) -> int:
        """Determine which of the 4 handshake messages this is from key_info flags.

        key_info bit flags (relevant ones):
          bit 3:  Install
          bit 6:  ACK
          bit 8:  MIC
          bit 9:  Secure

        Message 1: ACK set, MIC not set (AP sends ANonce)
        Message 2: MIC set, ACK not set (Client sends SNonce + MIC)
        Message 3: ACK set, MIC set, Install set (AP confirms, sends GTK)
        Message 4: MIC set, ACK not set, Secure set (Client confirms)
        """
        install = bool(key_info & (1 << 6))  # bit 6 in some implementations
        ack = bool(key_info & (1 << 7))      # bit 7
        mic_set = bool(key_info & (1 << 8))  # bit 8
        secure = bool(key_info & (1 << 9))   # bit 9

        has_nonce = nonce != b"\x00" * 32 and len(nonce) == 32
        has_mic = mic != b"\x00" * 16 and len(mic) >= 16

        if ack and not has_mic:
            return 1
        if not ack and has_mic and has_nonce:
            return 2
        if ack and has_mic:
            return 3
        if not ack and has_mic and not has_nonce:
            return 4

        # Fallback: use bit flags only
        if ack and not mic_set:
            return 1
        if not ack and mic_set and not secure:
            return 2
        if ack and mic_set:
            return 3
        if not ack and mic_set and secure:
            return 4

        return 0  # indeterminate

    @staticmethod
    def _freq_to_channel(freq: int) -> int | None:
        """Convert WiFi frequency (MHz) to channel number."""
        # 2.4 GHz band
        if 2412 <= freq <= 2472:
            return (freq - 2407) // 5
        if freq == 2484:
            return 14
        # 5 GHz band
        if 5180 <= freq <= 5825:
            return (freq - 5000) // 5
        return None
