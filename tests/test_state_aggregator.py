import asyncio
import time

import pytest

from config import Config
from state_aggregator import StateAggregator
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
    AccessPointState,
    ClientState,
    AssociationState,
    AssociationStatus,
    HandshakeState,
    EncryptionType,
)


@pytest.fixture
def config():
    return Config()


@pytest.fixture
def agg(config):
    return StateAggregator(config, vendor_lookup=lambda mac: "TestVendor")


def _base(ts=1000.0, signal=-50, channel=6, src="cc:cc:cc:cc:cc:cc",
           dst="dd:dd:dd:dd:dd:dd", bssid="aa:bb:cc:dd:ee:ff"):
    return dict(
        timestamp=ts, signal_dbm=signal, channel=channel,
        source_mac=src, dest_mac=dst, bssid=bssid, frame_length=100,
        raw_packet=None,
    )


# ------------------------------------------------------------------
# Beacon handling
# ------------------------------------------------------------------

class TestBeacons:
    def test_new_ap_registered(self, agg):
        frame = BeaconFrame(**_base(), ssid="Home", encryption_type=EncryptionType.WPA2)
        asyncio.run(agg.process_frame(frame))

        assert "aa:bb:cc:dd:ee:ff" in agg.aps
        ap = agg.aps["aa:bb:cc:dd:ee:ff"]
        assert ap.ssid == "Home"
        assert ap.encryption == EncryptionType.WPA2
        assert ap.channel == 6
        assert ap.beacon_count == 1
        assert ap.vendor == "TestVendor"

    def test_beacon_updates_existing_ap(self, agg):
        f1 = BeaconFrame(**_base(ts=1000.0), ssid="Home", encryption_type=EncryptionType.WPA2)
        f2 = BeaconFrame(**_base(ts=1001.0, signal=-45), ssid="Home", encryption_type=EncryptionType.WPA2)
        asyncio.run(agg.process_frame(f1))
        asyncio.run(agg.process_frame(f2))

        ap = agg.aps["aa:bb:cc:dd:ee:ff"]
        assert ap.beacon_count == 2
        assert ap.last_seen == 1001.0
        assert len(ap.signal_dbm_history) == 2

    def test_hidden_ssid_detected(self, agg):
        frame = BeaconFrame(**_base(), ssid="<hidden>", encryption_type=EncryptionType.WPA2)
        asyncio.run(agg.process_frame(frame))

        ap = agg.aps["aa:bb:cc:dd:ee:ff"]
        assert ap.hidden_ssid is True

    def test_hidden_ssid_revealed_by_later_beacon(self, agg):
        f1 = BeaconFrame(**_base(ts=1000.0), ssid="<hidden>", encryption_type=EncryptionType.WPA2)
        f2 = BeaconFrame(**_base(ts=1001.0), ssid="SecretNet", encryption_type=EncryptionType.WPA2)
        asyncio.run(agg.process_frame(f1))
        asyncio.run(agg.process_frame(f2))

        ap = agg.aps["aa:bb:cc:dd:ee:ff"]
        assert ap.ssid == "SecretNet"
        assert ap.hidden_ssid is False

    def test_no_bssid_ignored(self, agg):
        frame = BeaconFrame(**_base(bssid=None), ssid="X", encryption_type=EncryptionType.OPEN)
        asyncio.run(agg.process_frame(frame))
        assert len(agg.aps) == 0


# ------------------------------------------------------------------
# Probe requests
# ------------------------------------------------------------------

class TestProbeRequests:
    def test_client_registered(self, agg):
        frame = ProbeRequest(
            **_base(src="11:22:33:44:55:66"),
            ssid="LookingFor",
            client_mac="11:22:33:44:55:66",
        )
        asyncio.run(agg.process_frame(frame))

        assert "11:22:33:44:55:66" in agg.clients
        assert "LookingFor" in agg.clients["11:22:33:44:55:66"].probe_history

    def test_broadcast_probe(self, agg):
        frame = ProbeRequest(
            **_base(src="11:22:33:44:55:66"),
            ssid=None,
            client_mac="11:22:33:44:55:66",
        )
        asyncio.run(agg.process_frame(frame))

        assert "11:22:33:44:55:66" in agg.clients
        assert len(agg.clients["11:22:33:44:55:66"].probe_history) == 0

    def test_duplicate_ssid_not_repeated(self, agg):
        for _ in range(3):
            frame = ProbeRequest(
                **_base(src="11:22:33:44:55:66"),
                ssid="Same",
                client_mac="11:22:33:44:55:66",
            )
            asyncio.run(agg.process_frame(frame))

        assert agg.clients["11:22:33:44:55:66"].probe_history.count("Same") == 1

    def test_probe_creates_association(self, agg):
        frame = ProbeRequest(
            **_base(src="11:22:33:44:55:66", bssid="aa:bb:cc:dd:ee:ff"),
            ssid="Target",
            client_mac="11:22:33:44:55:66",
        )
        asyncio.run(agg.process_frame(frame))

        key = ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        assert key in agg.associations
        assert agg.associations[key].status == AssociationStatus.PROBING


# ------------------------------------------------------------------
# Probe responses
# ------------------------------------------------------------------

class TestProbeResponses:
    def test_reveals_hidden_ssid(self, agg):
        # First register AP with hidden SSID
        beacon = BeaconFrame(**_base(), ssid="<hidden>", encryption_type=EncryptionType.WPA2)
        asyncio.run(agg.process_frame(beacon))

        # Probe response reveals it
        resp = ProbeResponse(
            **_base(src="aa:bb:cc:dd:ee:ff"),
            ssid="RevealedName",
            ap_mac="aa:bb:cc:dd:ee:ff",
        )
        asyncio.run(agg.process_frame(resp))

        assert agg.aps["aa:bb:cc:dd:ee:ff"].ssid == "RevealedName"
        assert agg.aps["aa:bb:cc:dd:ee:ff"].hidden_ssid is False


# ------------------------------------------------------------------
# Authentication + Association
# ------------------------------------------------------------------

class TestAssociation:
    def test_auth_creates_association(self, agg):
        frame = AuthenticationFrame(
            **_base(),
            client_mac="11:22:33:44:55:66",
            ap_mac="aa:bb:cc:dd:ee:ff",
            algorithm=0,
            status_code=0,
        )
        asyncio.run(agg.process_frame(frame))

        key = ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        assert agg.associations[key].status == AssociationStatus.AUTHENTICATING

    def test_assoc_response_success(self, agg):
        frame = AssociationResponse(
            **_base(),
            client_mac="11:22:33:44:55:66",
            ap_mac="aa:bb:cc:dd:ee:ff",
            status_code=0,
        )
        asyncio.run(agg.process_frame(frame))

        key = ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        assert agg.associations[key].status == AssociationStatus.ASSOCIATED
        assert agg.clients["11:22:33:44:55:66"].associated_bssid == "aa:bb:cc:dd:ee:ff"

    def test_full_association_lifecycle(self, agg):
        client = "11:22:33:44:55:66"
        ap = "aa:bb:cc:dd:ee:ff"
        key = (ap, client)

        # Probe
        asyncio.run(agg.process_frame(ProbeRequest(
            **_base(src=client, bssid=ap, ts=1.0), ssid="Net", client_mac=client,
        )))
        assert agg.associations[key].status == AssociationStatus.PROBING

        # Auth
        asyncio.run(agg.process_frame(AuthenticationFrame(
            **_base(ts=2.0), client_mac=client, ap_mac=ap, algorithm=0, status_code=0,
        )))
        assert agg.associations[key].status == AssociationStatus.AUTHENTICATING

        # Assoc response
        asyncio.run(agg.process_frame(AssociationResponse(
            **_base(ts=3.0), client_mac=client, ap_mac=ap, status_code=0,
        )))
        assert agg.associations[key].status == AssociationStatus.ASSOCIATED


# ------------------------------------------------------------------
# Deauth / Disassociation
# ------------------------------------------------------------------

class TestDeauth:
    def test_deauth_disconnects_client(self, agg):
        client = "11:22:33:44:55:66"
        ap = "aa:bb:cc:dd:ee:ff"

        # Register AP and associate client
        asyncio.run(agg.process_frame(BeaconFrame(
            **_base(), ssid="Net", encryption_type=EncryptionType.WPA2,
        )))
        asyncio.run(agg.process_frame(AssociationResponse(
            **_base(), client_mac=client, ap_mac=ap, status_code=0,
        )))
        assert agg.clients[client].associated_bssid == ap

        # Deauth from AP
        asyncio.run(agg.process_frame(DeauthFrame(
            **_base(src=ap, dst=client, ts=1001.0),
            sender_mac=ap, target_mac=client, reason_code=7,
        )))

        key = (ap, client)
        assert agg.associations[key].status == AssociationStatus.DISCONNECTED
        assert agg.clients[client].associated_bssid is None

    def test_disassoc_disconnects_client(self, agg):
        client = "11:22:33:44:55:66"
        ap = "aa:bb:cc:dd:ee:ff"

        asyncio.run(agg.process_frame(BeaconFrame(
            **_base(), ssid="Net", encryption_type=EncryptionType.WPA2,
        )))
        asyncio.run(agg.process_frame(AssociationResponse(
            **_base(), client_mac=client, ap_mac=ap, status_code=0,
        )))

        asyncio.run(agg.process_frame(DisassociationFrame(
            **_base(src=ap, dst=client, ts=1001.0),
            sender_mac=ap, target_mac=client, reason_code=3,
        )))

        key = (ap, client)
        assert agg.associations[key].status == AssociationStatus.DISCONNECTED


# ------------------------------------------------------------------
# EAPOL / Handshake tracking
# ------------------------------------------------------------------

class TestHandshakeTracking:
    def test_single_eapol_message(self, agg):
        frame = EAPOLFrame(
            **_base(),
            client_mac="11:22:33:44:55:66",
            ap_mac="aa:bb:cc:dd:ee:ff",
            key_info=0x0080,
            message_number=1,
            nonce=b"\x11" * 32,
            mic=b"\x00" * 16,
        )
        asyncio.run(agg.process_frame(frame))

        key = ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        assert key in agg.handshakes
        assert agg.handshakes[key].captured_messages == [1]
        assert agg.handshakes[key].complete is False

    def test_complete_handshake(self, agg):
        completed = []
        agg.on_handshake_complete(lambda hs: completed.append(hs))

        client = "11:22:33:44:55:66"
        ap = "aa:bb:cc:dd:ee:ff"

        for msg_num in [1, 2, 3, 4]:
            frame = EAPOLFrame(
                **_base(ts=1000.0 + msg_num),
                client_mac=client, ap_mac=ap,
                key_info=0, message_number=msg_num,
                nonce=b"\x00" * 32, mic=b"\x00" * 16,
            )
            asyncio.run(agg.process_frame(frame))

        key = (ap, client)
        assert agg.handshakes[key].complete is True
        assert agg.handshakes[key].attempts == 1
        assert len(completed) == 1

    def test_3_of_4_is_complete(self, agg):
        client = "11:22:33:44:55:66"
        ap = "aa:bb:cc:dd:ee:ff"

        for msg_num in [1, 2, 3]:
            frame = EAPOLFrame(
                **_base(ts=1000.0 + msg_num),
                client_mac=client, ap_mac=ap,
                key_info=0, message_number=msg_num,
                nonce=b"\x00" * 32, mic=b"\x00" * 16,
            )
            asyncio.run(agg.process_frame(frame))

        key = (ap, client)
        assert agg.handshakes[key].complete is True

    def test_callback_only_fires_once(self, agg):
        completed = []
        agg.on_handshake_complete(lambda hs: completed.append(hs))

        client = "11:22:33:44:55:66"
        ap = "aa:bb:cc:dd:ee:ff"

        # Send all 4 messages twice
        for _ in range(2):
            for msg_num in [1, 2, 3, 4]:
                frame = EAPOLFrame(
                    **_base(ts=1000.0 + msg_num),
                    client_mac=client, ap_mac=ap,
                    key_info=0, message_number=msg_num,
                    nonce=b"\x00" * 32, mic=b"\x00" * 16,
                )
                asyncio.run(agg.process_frame(frame))

        assert len(completed) == 1

    def test_get_complete_handshakes(self, agg):
        client = "11:22:33:44:55:66"
        ap = "aa:bb:cc:dd:ee:ff"

        for msg_num in [1, 2, 3]:
            frame = EAPOLFrame(
                **_base(ts=1000.0 + msg_num),
                client_mac=client, ap_mac=ap,
                key_info=0, message_number=msg_num,
                nonce=b"\x00" * 32, mic=b"\x00" * 16,
            )
            asyncio.run(agg.process_frame(frame))

        assert len(agg.get_complete_handshakes()) == 1


# ------------------------------------------------------------------
# Data frames
# ------------------------------------------------------------------

class TestDataFrames:
    def test_data_frame_associates_client(self, agg):
        # Register AP first
        asyncio.run(agg.process_frame(BeaconFrame(
            **_base(), ssid="Net", encryption_type=EncryptionType.WPA2,
        )))

        frame = DataFrame(
            **_base(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff",
                    bssid="aa:bb:cc:dd:ee:ff"),
            encrypted=True, qos=False,
        )
        asyncio.run(agg.process_frame(frame))

        assert "11:22:33:44:55:66" in agg.clients
        client = agg.clients["11:22:33:44:55:66"]
        assert client.data_frame_count == 1
        assert client.associated_bssid == "aa:bb:cc:dd:ee:ff"

    def test_data_frame_increments_count(self, agg):
        asyncio.run(agg.process_frame(BeaconFrame(
            **_base(), ssid="Net", encryption_type=EncryptionType.WPA2,
        )))

        for i in range(5):
            frame = DataFrame(
                **_base(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff",
                        bssid="aa:bb:cc:dd:ee:ff", ts=1000.0 + i),
                encrypted=True, qos=False,
            )
            asyncio.run(agg.process_frame(frame))

        assert agg.clients["11:22:33:44:55:66"].data_frame_count == 5
        key = ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
        assert agg.associations[key].data_frame_count == 5

    def test_data_from_ap_to_client(self, agg):
        # AP sending to client: src=BSSID, dst=client
        asyncio.run(agg.process_frame(BeaconFrame(
            **_base(), ssid="Net", encryption_type=EncryptionType.WPA2,
        )))

        frame = DataFrame(
            **_base(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66",
                    bssid="aa:bb:cc:dd:ee:ff"),
            encrypted=True, qos=False,
        )
        asyncio.run(agg.process_frame(frame))

        # Client should be the dst, not the src (which is the AP)
        assert "11:22:33:44:55:66" in agg.clients
        assert agg.clients["11:22:33:44:55:66"].data_frame_count == 1


# ------------------------------------------------------------------
# Query helpers
# ------------------------------------------------------------------

class TestQueries:
    def test_get_ap_client_count(self, agg):
        ap = "aa:bb:cc:dd:ee:ff"
        asyncio.run(agg.process_frame(BeaconFrame(
            **_base(), ssid="Net", encryption_type=EncryptionType.WPA2,
        )))

        for i in range(3):
            client = f"11:22:33:44:55:{i:02x}"
            asyncio.run(agg.process_frame(AssociationResponse(
                **_base(), client_mac=client, ap_mac=ap, status_code=0,
            )))

        assert agg.get_ap_client_count(ap) == 3

    def test_get_clients_for_ap(self, agg):
        ap = "aa:bb:cc:dd:ee:ff"
        asyncio.run(agg.process_frame(BeaconFrame(
            **_base(), ssid="Net", encryption_type=EncryptionType.WPA2,
        )))
        asyncio.run(agg.process_frame(AssociationResponse(
            **_base(), client_mac="11:22:33:44:55:66", ap_mac=ap, status_code=0,
        )))

        clients = agg.get_clients_for_ap(ap)
        assert len(clients) == 1
        assert clients[0].mac == "11:22:33:44:55:66"

    def test_get_ap_for_client(self, agg):
        ap = "aa:bb:cc:dd:ee:ff"
        asyncio.run(agg.process_frame(BeaconFrame(
            **_base(), ssid="Net", encryption_type=EncryptionType.WPA2,
        )))
        asyncio.run(agg.process_frame(AssociationResponse(
            **_base(), client_mac="11:22:33:44:55:66", ap_mac=ap, status_code=0,
        )))

        result = agg.get_ap_for_client("11:22:33:44:55:66")
        assert result is not None
        assert result.bssid == ap

    def test_get_ap_for_unknown_client(self, agg):
        assert agg.get_ap_for_client("ff:ff:ff:ff:ff:ff") is None

    def test_frame_count(self, agg):
        for i in range(10):
            asyncio.run(agg.process_frame(BeaconFrame(
                **_base(ts=1000.0 + i), ssid="Net", encryption_type=EncryptionType.WPA2,
            )))
        assert agg.frame_count == 10
