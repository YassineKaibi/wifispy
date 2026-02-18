import asyncio
import threading
from unittest.mock import patch, MagicMock

import pytest

from config import Config
from capture_engine import CaptureEngine
from exceptions import CaptureError


@pytest.fixture
def config():
    return Config()


@pytest.fixture
def engine(config):
    return CaptureEngine(config, interface="wlan0mon")


# ------------------------------------------------------------------
# start / stop lifecycle
# ------------------------------------------------------------------

class TestLifecycle:
    @patch("capture_engine._init_scapy")
    def test_start_creates_thread(self, mock_init, engine):
        # Mock sniff that blocks until stop_event is set
        def blocking_sniff(**kwargs):
            while not engine._stop_event.is_set():
                import time; time.sleep(0.01)
        mock_init.return_value = blocking_sniff
        loop = asyncio.new_event_loop()
        try:
            engine.start(loop)
            import time; time.sleep(0.05)
            assert engine._thread is not None
            assert engine._thread.is_alive()
            engine.stop()
        finally:
            loop.close()

    @patch("capture_engine._init_scapy")
    def test_stop_joins_thread(self, mock_init, engine):
        def blocking_sniff(**kwargs):
            while not engine._stop_event.is_set():
                import time; time.sleep(0.01)
        mock_init.return_value = blocking_sniff
        loop = asyncio.new_event_loop()
        try:
            engine.start(loop)
            engine.stop()
            assert engine._thread is None
        finally:
            loop.close()

    @patch("capture_engine._init_scapy")
    def test_double_start_ignored(self, mock_init, engine):
        def blocking_sniff(**kwargs):
            while not engine._stop_event.is_set():
                import time; time.sleep(0.01)
        mock_init.return_value = blocking_sniff
        loop = asyncio.new_event_loop()
        try:
            engine.start(loop)
            import time; time.sleep(0.05)
            first_thread = engine._thread
            engine.start(loop)
            assert engine._thread is first_thread
            engine.stop()
        finally:
            loop.close()

    @patch("capture_engine._init_scapy")
    def test_stop_when_not_started(self, mock_init, engine):
        engine.stop()  # should not raise


# ------------------------------------------------------------------
# _on_packet
# ------------------------------------------------------------------

class TestOnPacket:
    def test_packet_count_increments(self, engine):
        loop = asyncio.new_event_loop()
        engine._loop = loop
        try:
            packet = MagicMock()
            engine._on_packet(packet)
            engine._on_packet(packet)
            assert engine.packet_count == 2
        finally:
            loop.close()

    def test_packet_pushed_to_queue(self, engine):
        loop = asyncio.new_event_loop()
        engine._loop = loop
        try:
            packet = MagicMock()
            engine._on_packet(packet)
            # run pending callbacks on the loop
            loop.run_until_complete(asyncio.sleep(0))
            assert engine.queue.qsize() == 1
        finally:
            loop.close()

    def test_drop_when_queue_full(self, engine):
        loop = asyncio.new_event_loop()
        engine._loop = loop
        engine._queue = asyncio.Queue(maxsize=2)
        try:
            engine._queue.put_nowait("p1")
            engine._queue.put_nowait("p2")
            engine._on_packet(MagicMock())
            assert engine.drop_count == 1
            assert engine._queue.qsize() == 2
        finally:
            loop.close()

    def test_no_push_without_loop(self, engine):
        engine._loop = None
        engine._on_packet(MagicMock())
        assert engine.packet_count == 1
        assert engine.queue.qsize() == 0  # nothing pushed


# ------------------------------------------------------------------
# extra callbacks
# ------------------------------------------------------------------

class TestCallbacks:
    def test_register_and_fire_callback(self, engine):
        loop = asyncio.new_event_loop()
        engine._loop = loop
        received = []
        engine.register_callback(lambda pkt: received.append(pkt))
        try:
            packet = MagicMock()
            engine._on_packet(packet)
            assert len(received) == 1
            assert received[0] is packet
        finally:
            loop.close()

    def test_callback_error_does_not_crash(self, engine):
        loop = asyncio.new_event_loop()
        engine._loop = loop

        def bad_callback(pkt):
            raise ValueError("boom")

        engine.register_callback(bad_callback)
        try:
            engine._on_packet(MagicMock())  # should not raise
            assert engine.packet_count == 1
        finally:
            loop.close()

    def test_multiple_callbacks(self, engine):
        loop = asyncio.new_event_loop()
        engine._loop = loop
        results = {"a": 0, "b": 0}
        engine.register_callback(lambda pkt: results.update(a=results["a"] + 1))
        engine.register_callback(lambda pkt: results.update(b=results["b"] + 1))
        try:
            engine._on_packet(MagicMock())
            assert results["a"] == 1
            assert results["b"] == 1
        finally:
            loop.close()

    def test_callbacks_are_per_instance(self):
        config = Config()
        engine1 = CaptureEngine(config, "wlan0mon")
        engine2 = CaptureEngine(config, "wlan0mon")
        engine1.register_callback(lambda pkt: None)
        assert len(engine1._extra_callbacks) == 1
        assert len(engine2._extra_callbacks) == 0


# ------------------------------------------------------------------
# get_packet
# ------------------------------------------------------------------

class TestGetPacket:
    def test_get_packet_returns_from_queue(self, engine):
        async def run():
            await engine._queue.put("test_packet")
            result = await engine.get_packet()
            assert result == "test_packet"

        asyncio.run(run())


# ------------------------------------------------------------------
# _sniff_worker error handling
# ------------------------------------------------------------------

class TestSniffWorker:
    @patch("capture_engine._init_scapy")
    def test_permission_error(self, mock_init, engine):
        mock_init.return_value = MagicMock(side_effect=PermissionError())
        with pytest.raises(CaptureError, match="permissions"):
            engine._sniff_worker()

    @patch("capture_engine._init_scapy")
    def test_os_error(self, mock_init, engine):
        mock_init.return_value = MagicMock(side_effect=OSError("No such device"))
        with pytest.raises(CaptureError, match="Sniff failed"):
            engine._sniff_worker()

    @patch("capture_engine._init_scapy")
    def test_os_error_during_shutdown_ignored(self, mock_init, engine):
        mock_init.return_value = MagicMock(side_effect=OSError("interrupted"))
        engine._stop_event.set()
        engine._sniff_worker()  # should not raise

    @patch("capture_engine._init_scapy")
    def test_unexpected_error(self, mock_init, engine):
        mock_init.return_value = MagicMock(side_effect=RuntimeError("unexpected"))
        with pytest.raises(CaptureError, match="unexpected"):
            engine._sniff_worker()

    @patch("capture_engine._init_scapy")
    def test_unexpected_error_during_shutdown_ignored(self, mock_init, engine):
        mock_init.return_value = MagicMock(side_effect=RuntimeError("shutdown"))
        engine._stop_event.set()
        engine._sniff_worker()  # should not raise
