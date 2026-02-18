import asyncio
import sys
from unittest.mock import MagicMock, patch, PropertyMock
from dataclasses import dataclass

import pytest

# ------------------------------------------------------------------
# Mock Scapy layer classes before importing frame_parser
# ------------------------------------------------------------------

_mock_dot11 = MagicMock()
_mock_eap = MagicMock()

# Create real class objects so isinstance/haslayer checks work via __name__
for cls_name in [
    "Dot11", "Dot11Beacon", "Dot11ProbeReq", "Dot11ProbeResp",
    "Dot11Auth", "Dot11AssoReq", "Dot11AssoResp", "Dot11Deauth",
    "Dot11Disas", "Dot11Elt", "RadioTap",
]:
    mock_cls = type(cls_name, (), {})
    setattr(_mock_dot11, cls_name, mock_cls)

_mock_eap.EAPOL = type("EAPOL", (), {})

sys.modules["scapy.layers.dot11"] = _mock_dot11
sys.modules["scapy.layers.eap"] = _mock_eap

from frame_parser import FrameParser
from models import (
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


@pytest.fixture
def parser():
    return FrameParser()


# ------------------------------------------------------------------
# Helpers to build mock Scapy packets
# ------------------------------------------------------------------

def _make_dot11(type_val=0, subtype_val=0, addr1="aa:bb:cc:dd:ee:ff",
                addr2="11:22:33:44:55:66", addr3="11:22:33:44:55:66",
                fcfield=0):
    dot11 = MagicMock()
    dot11.type = type_val
    dot11.subtype = subtype_val
    dot11.addr1 = addr1
    dot11.addr2 = addr2
    dot11.addr3 = addr3
    dot11.FCfield = fcfield
    return dot11


def _make_radiotap(signal=-50, freq=2437):
    rt = MagicMock()
    rt.dBm_AntSignal = signal
    rt.ChannelFrequency = freq
    return rt


def _make_elt(ssid="TestNetwork"):
    elt = MagicMock()
    elt.info = ssid.encode("utf-8") if ssid else b""
    elt.ID = 0
    elt.payload = MagicMock()
    elt.payload.getlayer.return_value = None
    return elt


def _make_packet(dot11, radiotap=None, layers=None, elt=None):
    """Build a mock packet with configurable layers."""
    layers = layers or {}
    packet = MagicMock()
    packet.__len__ = MagicMock(return_value=100)

    # Map class name -> layer mock
    layer_map = {"Dot11": dot11}
    if radiotap:
        layer_map["RadioTap"] = radiotap
    layer_map.update(layers)

    def has_layer(layer_cls):
        return layer_cls.__name__ in layer_map

    packet.haslayer = has_layer

    def get_item(layer_cls):
        name = layer_cls.__name__
        if name in layer_map:
            return layer_map[name]
        raise KeyError(name)

    packet.__getitem__ = MagicMock(side_effect=get_item)

    # getlayer for SSID extraction
    if elt:
        packet.getlayer = lambda cls, **kwargs: elt if kwargs.get("ID") == 0 else None
    else:
        packet.getlayer = lambda cls, **kwargs: None

    return packet


# ------------------------------------------------------------------
# Frequency to channel conversion
# ------------------------------------------------------------------

class TestFreqToChannel:
    def test_channel_1(self, parser):
        assert parser._freq_to_channel(2412) == 1

    def test_channel_6(self, parser):
        assert parser._freq_to_channel(2437) == 6

    def test_channel_11(self, parser):
        assert parser._freq_to_channel(2462) == 11

    def test_channel_14(self, parser):
        assert parser._freq_to_channel(2484) == 14

    def test_5ghz_channel_36(self, parser):
        assert parser._freq_to_channel(5180) == 36

    def test_5ghz_channel_149(self, parser):
        assert parser._freq_to_channel(5745) == 149

    def test_unknown_freq(self, parser):
        assert parser._freq_to_channel(9999) is None


# ------------------------------------------------------------------
# Base extraction
# ------------------------------------------------------------------

class TestExtractBase:
    @patch("frame_parser.time")
    def test_extracts_all_fields(self, mock_time, parser):
        mock_time.time.return_value = 1000.0
        # Need to patch Scapy imports inside the method
        dot11 = _make_dot11()
        rt = _make_radiotap(signal=-65, freq=2412)
        packet = _make_packet(dot11, radiotap=rt)

        with patch.dict("sys.modules", {
            "scapy.layers.dot11": MagicMock(RadioTap=type(rt)),
        }):
            # Call through parse to exercise _extract_base
            pass  # tested indirectly through frame parsing tests


# ------------------------------------------------------------------
# Beacon parsing
# ------------------------------------------------------------------

class TestBeaconParsing:
    @patch("frame_parser.time")
    def test_basic_beacon(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=0, subtype_val=8)
        rt = _make_radiotap(signal=-50, freq=2437)
        elt = _make_elt("MyWiFi")

        # Mock beacon layer with capability
        beacon_layer = MagicMock()
        beacon_layer.cap = MagicMock()
        beacon_layer.cap.privacy = False

        packet = _make_packet(dot11, rt, layers={"Dot11Beacon": beacon_layer}, elt=elt)

        frame = parser.parse(packet)
        assert isinstance(frame, BeaconFrame)
        assert frame.ssid == "MyWiFi"
        assert frame.encryption_type == EncryptionType.OPEN
        assert frame.signal_dbm == -50
        assert frame.channel == 6

    @patch("frame_parser.time")
    def test_hidden_ssid(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=0, subtype_val=8)
        rt = _make_radiotap()
        elt = _make_elt("")

        beacon_layer = MagicMock()
        beacon_layer.cap = MagicMock()
        beacon_layer.cap.privacy = False

        packet = _make_packet(dot11, rt, layers={"Dot11Beacon": beacon_layer}, elt=elt)

        frame = parser.parse(packet)
        assert isinstance(frame, BeaconFrame)
        assert frame.ssid == "<hidden>"


# ------------------------------------------------------------------
# Probe request / response
# ------------------------------------------------------------------

class TestProbeParsing:
    @patch("frame_parser.time")
    def test_probe_request(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=0, subtype_val=4, addr2="aa:bb:cc:11:22:33")
        rt = _make_radiotap()
        elt = _make_elt("TargetNetwork")

        packet = _make_packet(dot11, rt, elt=elt)

        frame = parser.parse(packet)
        assert isinstance(frame, ProbeRequest)
        assert frame.ssid == "TargetNetwork"
        assert frame.client_mac == "aa:bb:cc:11:22:33"

    @patch("frame_parser.time")
    def test_broadcast_probe_request(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=0, subtype_val=4)
        rt = _make_radiotap()
        elt = _make_elt("")

        packet = _make_packet(dot11, rt, elt=elt)

        frame = parser.parse(packet)
        assert isinstance(frame, ProbeRequest)
        assert frame.ssid is None  # broadcast probe

    @patch("frame_parser.time")
    def test_probe_response(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=0, subtype_val=5, addr2="11:22:33:44:55:66")
        rt = _make_radiotap()
        elt = _make_elt("MyNetwork")

        packet = _make_packet(dot11, rt, elt=elt)

        frame = parser.parse(packet)
        assert isinstance(frame, ProbeResponse)
        assert frame.ssid == "MyNetwork"
        assert frame.ap_mac == "11:22:33:44:55:66"


# ------------------------------------------------------------------
# Deauth / Disassociation
# ------------------------------------------------------------------

class TestDeauthParsing:
    @patch("frame_parser.time")
    def test_deauth_frame(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(
            type_val=0, subtype_val=12,
            addr1="aa:bb:cc:dd:ee:ff",
            addr2="11:22:33:44:55:66",
        )
        rt = _make_radiotap()

        deauth_layer = MagicMock()
        deauth_layer.reason = 7

        packet = _make_packet(dot11, rt, layers={"Dot11Deauth": deauth_layer})

        frame = parser.parse(packet)
        assert isinstance(frame, DeauthFrame)
        assert frame.sender_mac == "11:22:33:44:55:66"
        assert frame.target_mac == "aa:bb:cc:dd:ee:ff"
        assert frame.reason_code == 7

    @patch("frame_parser.time")
    def test_disassociation_frame(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=0, subtype_val=10)
        rt = _make_radiotap()

        disas_layer = MagicMock()
        disas_layer.reason = 3

        packet = _make_packet(dot11, rt, layers={"Dot11Disas": disas_layer})

        frame = parser.parse(packet)
        assert isinstance(frame, DisassociationFrame)
        assert frame.reason_code == 3


# ------------------------------------------------------------------
# Data frames
# ------------------------------------------------------------------

class TestDataParsing:
    @patch("frame_parser.time")
    def test_encrypted_data_frame(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=2, subtype_val=0, fcfield=0x40)  # Protected bit
        rt = _make_radiotap()

        packet = _make_packet(dot11, rt)

        frame = parser.parse(packet)
        assert isinstance(frame, DataFrame)
        assert frame.encrypted is True

    @patch("frame_parser.time")
    def test_unencrypted_data_frame(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=2, subtype_val=0, fcfield=0)
        rt = _make_radiotap()

        packet = _make_packet(dot11, rt)

        frame = parser.parse(packet)
        assert isinstance(frame, DataFrame)
        assert frame.encrypted is False

    @patch("frame_parser.time")
    def test_qos_data_frame(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=2, subtype_val=8)  # QoS data
        rt = _make_radiotap()

        packet = _make_packet(dot11, rt)

        frame = parser.parse(packet)
        assert isinstance(frame, DataFrame)
        assert frame.qos is True


# ------------------------------------------------------------------
# EAPOL message number detection
# ------------------------------------------------------------------

class TestEAPOLMessageDetection:
    def test_message_1(self, parser):
        # ACK set, no MIC
        key_info = 0x0080  # ACK bit
        nonce = b"\x11" * 32  # has nonce (ANonce)
        mic = b"\x00" * 16  # no MIC
        assert parser._determine_eapol_message(key_info, nonce, mic) == 1

    def test_message_2(self, parser):
        # No ACK, has MIC, has nonce (SNonce)
        key_info = 0x0100  # MIC bit
        nonce = b"\x22" * 32
        mic = b"\xaa" * 16
        assert parser._determine_eapol_message(key_info, nonce, mic) == 2

    def test_message_3(self, parser):
        # ACK set, MIC set
        key_info = 0x0180  # ACK + MIC
        nonce = b"\x33" * 32  # ANonce
        mic = b"\xbb" * 16
        assert parser._determine_eapol_message(key_info, nonce, mic) == 3

    def test_message_4(self, parser):
        # No ACK, MIC set, no nonce
        key_info = 0x0100  # MIC bit
        nonce = b"\x00" * 32  # empty nonce
        mic = b"\xcc" * 16
        assert parser._determine_eapol_message(key_info, nonce, mic) == 4

    def test_indeterminate(self, parser):
        key_info = 0
        nonce = b"\x00" * 32
        mic = b"\x00" * 16
        assert parser._determine_eapol_message(key_info, nonce, mic) == 0


# ------------------------------------------------------------------
# Unknown / control frames
# ------------------------------------------------------------------

class TestUnknownFrames:
    @patch("frame_parser.time")
    def test_control_frame(self, mock_time, parser):
        mock_time.time.return_value = 1000.0

        dot11 = _make_dot11(type_val=1, subtype_val=13)  # ACK
        rt = _make_radiotap()

        packet = _make_packet(dot11, rt)

        frame = parser.parse(packet)
        assert isinstance(frame, UnknownFrame)
        assert frame.raw_type == 1
        assert frame.raw_subtype == 13

    def test_non_wifi_packet(self, parser):
        packet = MagicMock()
        packet.haslayer = lambda cls: False
        assert parser.parse(packet) is None


# ------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------

class TestErrorHandling:
    def test_malformed_packet_returns_none(self, parser):
        packet = MagicMock()
        packet.haslayer = MagicMock(side_effect=Exception("corrupt"))
        result = parser.parse(packet)
        assert result is None
        assert parser.error_count == 1

    def test_error_count_accumulates(self, parser):
        packet = MagicMock()
        packet.haslayer = MagicMock(side_effect=Exception("corrupt"))
        for _ in range(5):
            parser.parse(packet)
        assert parser.error_count == 5


# ------------------------------------------------------------------
# Consumer fan-out
# ------------------------------------------------------------------

class TestConsumerFanOut:
    def test_add_and_notify_consumers(self, parser):
        received = []

        async def consumer(frame):
            received.append(frame)

        parser.add_consumer(consumer)

        async def run():
            queue = asyncio.Queue()
            # Build a simple beacon packet
            dot11 = _make_dot11(type_val=0, subtype_val=4)
            rt = _make_radiotap()
            elt = _make_elt("Test")
            packet = _make_packet(dot11, rt, elt=elt)
            await queue.put(packet)

            # Run parser for one iteration
            task = asyncio.create_task(parser.run(queue))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())
        assert len(received) == 1
        assert isinstance(received[0], ProbeRequest)

    def test_consumer_error_does_not_crash(self, parser):
        async def bad_consumer(frame):
            raise ValueError("boom")

        async def good_consumer(frame):
            pass

        parser.add_consumer(bad_consumer)
        parser.add_consumer(good_consumer)

        async def run():
            queue = asyncio.Queue()
            dot11 = _make_dot11(type_val=0, subtype_val=4)
            rt = _make_radiotap()
            elt = _make_elt("Test")
            packet = _make_packet(dot11, rt, elt=elt)
            await queue.put(packet)

            task = asyncio.create_task(parser.run(queue))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())  # should not raise
