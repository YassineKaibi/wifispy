# WifiSpy - Full System Architecture

A Python CLI application running on WSL2 that performs passive wireless network analysis, intrusion detection, handshake capture, and serves as a framework for offensive testing integration. It interfaces with a monitor-mode WiFi adapter via USB passthrough and uses Scapy for direct 802.11 frame capture and parsing.

---

## Entry Point and Wiring

`main.py` bootstraps the application. It initializes all layers in dependency order: Interface Manager first (validates hardware), then Capture Engine, Frame Parser, State Aggregator, Alert Engine, PCAP Exporter, and finally the CLI Renderer and Command Handler.

Concurrency is handled via `asyncio` with a dedicated thread for Scapy's blocking sniff loop. Shutdown is graceful -- `SIGINT` / `SIGTERM` triggers a cascade that stops capture, restores the interface to managed mode, and flushes any pending pcap writes. A `signal` handler sets a threading `Event` that all layers check.

---

## Layer 1: Interface Manager

**File:** `interface_manager.py`

Owns the WiFi adapter lifecycle. On startup, it runs `iwconfig` via `subprocess.run`, parses the output to find wireless interfaces, and validates that the adapter supports monitor mode. It exposes three operations:

- Enable monitor mode: `airmon-ng start wlan0`
- Disable monitor mode: `airmon-ng stop wlan0mon`
- Set channel: `iwconfig wlan0mon channel N`

Channel hopping runs as a dedicated `asyncio` task. It cycles through 2.4GHz channels (1, 6, 11 first since those are most used, then the rest) and optionally 5GHz channels. The hop interval is configurable, defaulting to 250ms. When the user targets a specific AP or triggers handshake capture, the hopper pauses and locks to that AP's channel.

The manager also handles `airmon-ng check kill` on startup to stop interfering processes (NetworkManager, wpa_supplicant) that would fight for adapter control.

Error handling: if the adapter disappears (USB disconnect), this layer detects it on the next subprocess call failure and propagates an error up to halt capture and notify the user.

All subprocess calls are wrapped in a utility function that checks return codes and raises typed exceptions (`AdapterNotFoundError`, `MonitorModeError`, etc.).

---

## Layer 2: Packet Capture Engine

**File:** `capture_engine.py`

Runs Scapy's `sniff()` in a dedicated `threading.Thread` since `sniff()` is blocking and cannot be awaited. Each captured packet is pushed into an `asyncio`-safe `queue.Queue` (or `janus` queue for bridging sync/async) that the frame parser consumes from.

```
sniff(iface="wlan0mon", prn=callback, store=0)
```

The `prn` callback receives each raw Scapy packet and puts it into the queue. `store=0` prevents Scapy from accumulating packets in memory.

Scapy gives us direct access to:
- Radiotap headers (RSSI, channel, data rate)
- 802.11 management frames (beacons, probes, auth, assoc, deauth)
- 802.11 data frames
- EAPOL frames (WPA handshake)

No subprocess intermediary needed -- Scapy uses raw L2 sockets directly.

A parallel `AsyncSniffer` can optionally write raw pcap to disk via Scapy's `wrpcap()` for full fidelity continuous capture.

---

## Layer 3: Frame Parser

**File:** `frame_parser.py`

Consumes raw Scapy packets from the capture queue and produces typed Python dataclass objects. This is a pure transformation layer with no state.

The dataclass hierarchy:

```
WiFiFrame (base: timestamp, signal_dbm, channel, source_mac, dest_mac, bssid, frame_length)
  +-- BeaconFrame (ssid, encryption_type, beacon_interval, supported_rates)
  +-- ProbeRequest (ssid (nullable -- can be wildcard/broadcast), client_mac)
  +-- ProbeResponse (ssid, ap_mac)
  +-- AuthenticationFrame (client_mac, ap_mac, algorithm, status_code)
  +-- AssociationRequest (client_mac, ap_mac, ssid)
  +-- AssociationResponse (client_mac, ap_mac, status_code)
  +-- DeauthFrame (sender_mac, target_mac, reason_code)
  +-- DisassociationFrame (sender_mac, target_mac, reason_code)
  +-- EAPOLFrame (client_mac, ap_mac, key_info, message_number (1-4), nonce, mic, raw_packet)
  +-- DataFrame (source_mac, dest_mac, encrypted (bool), qos (bool))
  +-- UnknownFrame (raw_type, raw_subtype)
```

Frame type detection uses Scapy's layer checking:
- `packet.haslayer(Dot11Beacon)` -- beacon
- `packet.haslayer(Dot11ProbeReq)` -- probe request
- `packet.haslayer(Dot11Deauth)` -- deauth
- `packet.haslayer(EAPOL)` -- handshake frame
- `packet.type == 2` -- data frame

The parser determines EAPOL message number (1-4) from the `key_info` flags:
- Message 1: has ANonce, no MIC
- Message 2: has SNonce and MIC
- Message 3: has ANonce and MIC with install bit set
- Message 4: has MIC with no nonces

Signal strength (RSSI) is extracted from the Radiotap header: `packet[RadioTap].dBm_AntSignal`.

Encryption type is derived from Scapy's parsed RSN/WPA information elements in beacon frames, or from the capability flags (`packet.cap` for privacy bit).

Malformed or unparseable packets are logged and counted (useful as a health metric) but don't crash the pipeline.

Parsed frames are distributed to multiple async consumers (aggregator, alert engine, pcap exporter) via an `asyncio` fan-out pattern -- either multiple queues or a simple observer/callback list.

---

## Layer 4: State Aggregator

**File:** `state_aggregator.py`

The central in-memory model of the wireless environment. Runs as an `asyncio` task consuming parsed frames from the frame parser, updating dictionaries that the CLI renderer reads.

### AP Registry (`dict[str, AccessPointState]`, keyed by BSSID)

- SSID, BSSID, channel, encryption type (Open/WEP/WPA/WPA2/WPA3)
- Signal strength (running average of last N beacon RSSI values via `collections.deque`)
- First seen, last seen timestamps
- Beacon count
- Associated client count (derived from association map)
- Hidden SSID flag (beacon with empty SSID but responses to directed probes)

### Client Registry (`dict[str, ClientState]`, keyed by client MAC)

- MAC address
- Currently associated AP BSSID (nullable if not associated)
- Signal strength (from probe/data frame RSSI)
- Probe history: ordered list of SSIDs this client has probed for. Reveals the client's network history -- what WiFi networks this device has connected to before. Useful for profiling.
- Data frame count (traffic volume indicator)
- First seen, last seen

### Association Map (`dict[tuple[str, str], AssociationState]`, keyed by (BSSID, client MAC))

- State enum: `PROBING`, `AUTHENTICATING`, `ASSOCIATED`, `DISCONNECTED`
- Transition timestamps
- Data frame count within this association

State transitions are derived from frame sequences: ProbeRequest/Response -> Authentication -> AssociationRequest/Response -> Data frames. DeauthFrame triggers transition to `DISCONNECTED`.

### Handshake Tracker (`dict[tuple[str, str], HandshakeState]`, keyed by (BSSID, client MAC))

- Tracks which of the 4 EAPOL messages have been captured
- Stores the raw Scapy packet for each captured message (needed for pcap export)
- Flags complete when all 4 are present (or minimally messages 1, 2, and 3 which is sufficient for key derivation)
- Timestamps for each message
- Multiple capture attempts tracked separately (a client can reconnect multiple times)

When a complete handshake is detected, the aggregator calls the PCAP exporter to automatically save it.

### Vendor Lookup (`oui_lookup.py`)

The first 3 bytes of any MAC address (OUI) identify the manufacturer. A local OUI database (IEEE MA-L, downloadable as CSV/txt, ~3MB) maps these to vendor names. So instead of seeing `DC:A6:32:XX:XX:XX`, you see `Raspberry Pi Foundation`. Loaded once at startup into a `dict`. The `manuf` Python package can also be used as an alternative.

---

## Layer 5: Alert Engine

**File:** `alert_engine.py`

A separate `asyncio` task consuming parsed frames in parallel with the aggregator, running detection heuristics.

### Deauth Flood Detection

Counts deauth frames per source MAC within a sliding time window (e.g., 10 seconds) using a `collections.deque` of timestamps per MAC. If the count exceeds a threshold (configurable, default 10), flag as attack. Cross-references the source MAC against the AP registry -- if the source claims to be an AP but the deauth volume is abnormal, it's likely spoofed.

### Evil Twin Detection

Monitors for multiple BSSIDs advertising the same SSID. Legitimate enterprise setups do this, but the alert fires if a new BSSID appears for a known SSID with a different encryption type or on an unusual channel, or if the signal strength profile doesn't match (sudden appearance of a strong signal for a known SSID).

### Rogue AP Detection

APs appearing on non-standard channels, APs with no encryption in an environment where all known APs use WPA2, or APs with SSIDs that are slight misspellings of known ones (e.g., "Corp-WiFi" vs "Corp_WiFi"). Fuzzy matching via `difflib.SequenceMatcher` or Levenshtein distance.

### Client Anomaly Detection

A client rapidly associating/disassociating (possible deauth victim), a client probing for many SSIDs in quick succession (reconnaissance behavior), or a client suddenly appearing with very strong signal on a previously quiet channel.

### Karma Attack Detection

An AP responding to every probe request regardless of SSID. Detected by observing probe responses from the same BSSID for multiple different SSIDs within a short window.

Alerts are stored in a `collections.deque(maxlen=100)` ring buffer. Each alert is a dataclass with severity (INFO/WARNING/CRITICAL), timestamp, description, and involved MACs.

---

## Layer 6: PCAP Exporter

**File:** `pcap_exporter.py`

Handles writing captured data to standard `.pcap` files for offline analysis in Wireshark or other tools. Uses Scapy's `wrpcap()` and `PcapWriter` for all file operations.

### Continuous Capture

A `PcapWriter` instance runs in append mode, writing every raw packet to a rotating set of pcap files (configurable max size, e.g., 100MB per file, keep last 5). File rotation is handled manually by checking file size and opening a new writer.

### Filtered Export

On user command, reads back pcap files with `rdpcap()` or `PcapReader` and filters by BSSID, client MAC, or frame type. Writes the subset to a new file. For example, "export all frames involving this BSSID" applies a filter: `pkt.addr1 == bssid or pkt.addr2 == bssid or pkt.addr3 == bssid`.

### Handshake Auto-Export

When the handshake tracker flags a complete capture, the exporter writes a minimal pcap containing the relevant beacon frame (which contains the SSID needed for key derivation) plus the EAPOL frames. The raw packets stored in the `HandshakeState` dataclass are written directly via `wrpcap()`. This file is ready for direct use with external tools.

---

## Layer 7: CLI Renderer and Command Handler

**Files:** `cli_renderer.py`, `command_handler.py`

The user interface layer. Two concurrent responsibilities: rendering the display and processing user input. Uses the `rich` library for formatted, colored table output.

### Renderer

Uses `rich.live.Live` for auto-refreshing display. Updates every 1 second by reading from the state aggregator. `rich.table.Table` for column-aligned output, `rich.panel.Panel` for sections, `rich.text.Text` for colored inline content.

Color scheme:
- Green: open networks
- Red: alerts, critical events
- Yellow: partial handshakes
- Cyan: complete handshakes
- Dim/gray: stale entries (last seen > 60s ago)

### Views (user switches between them via keyboard commands)

1. **Dashboard** (default): Split view showing top 10 APs by signal strength and recent alerts. Quick status line showing total APs, total clients, total handshakes captured, capture duration, current channel.

2. **AP List**: Full table of all discovered APs. Columns: SSID, BSSID, Channel, Encryption, Signal (dBm), Clients, Beacons, First Seen, Last Seen, Vendor. Sortable by any column.

3. **Client List**: All observed clients. Columns: MAC, Vendor, Associated AP, Signal, Probed SSIDs (truncated), Data Frames, First Seen, Last Seen.

4. **Topology**: Tree view using `rich.tree.Tree`. Each AP as a root node with its associated clients as children. Shows signal strength and data volume for each link.

5. **Handshake Monitor**: Table of all client-AP pairs where at least one EAPOL frame has been captured. Shows which messages (1/2/3/4) are captured, timestamps, and completeness status.

6. **Alert Log**: Scrollable list of all alerts with full details, color-coded by severity.

7. **AP Detail**: Select a specific AP to see all its clients, traffic stats, channel history, and any related alerts. Also shows probe requests directed at this AP's SSID from unassociated clients.

8. **Client Detail**: Select a specific client to see its full probe history, association history, traffic pattern, and any captured handshake state.

### Command Handler

Reads stdin asynchronously via `asyncio` loop's `add_reader` or `aioconsole.ainput()`. Commands:

- `1`-`8` or named shortcuts to switch views
- `sort <column>` to change sort order
- `lock <channel>` to stop channel hopping and fix on a channel
- `hop` to resume channel hopping
- `target <bssid>` to lock channel to a specific AP and focus capture
- `export <bssid>` to export pcap for a specific AP
- `export handshake <bssid> <client>` to export captured handshake
- `clear alerts` to clear the alert log
- `status` to show interface state, capture stats, uptime
- `quit` to graceful shutdown

---

## Deauth Module (Offensive Testing)

**File:** `deauth_module.py`

Sits alongside the other layers, reads target info from the AP and Client registries. Uses pure Scapy to construct and inject deauthentication frames -- no external tools needed. Requires the interface manager to have the channel locked to the target AP.

Frame construction uses Scapy's packet layering:

```
RadioTap() / Dot11(addr1=target, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
```

Injection uses `sendp()` on the monitor-mode interface. For broadcast deauth (all clients), `addr1` is set to `ff:ff:ff:ff:ff:ff`. For targeted deauth, `addr1` is the specific client MAC. Frames are sent in configurable bursts (default 64 frames per burst) with a configurable inter-burst delay.

The module also sends the reverse direction frame (spoofing the client to the AP) for more effective disconnection:

```
RadioTap() / Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth(reason=7)
```

Operationally: user selects a target from the AP list, optionally selects a specific client, specifies burst count, and executes. The capture engine and aggregator continue running during the attack, so you observe the deauth frames going out, clients disconnecting, reconnecting, and EAPOL handshakes being captured -- all in real time across the different views.

The feedback loop is the project's key demonstration: offensive action observed and analyzed by the defensive tooling in the same system.

---

## Concurrency Model

Everything runs in a single Python process using `asyncio` with one background thread:

- **Thread 1 (sync):** Scapy `sniff()` loop -- blocking call, pushes packets into a thread-safe queue
- **Task 1:** Interface manager channel hopper (`asyncio.sleep` between hops)
- **Task 2:** Frame parser (pulls from sync queue, parses, fans out to consumers)
- **Task 3:** State aggregator (consumes parsed frames, updates in-memory model)
- **Task 4:** Alert engine (consumes parsed frames, runs detection heuristics)
- **Task 5:** CLI renderer (periodic tick via `rich.live.Live`, reads from aggregator)
- **Task 6:** PCAP writer (continuous capture, consumes raw packets)
- **Main task:** Command handler (async stdin reads)

The bridge between the sync sniff thread and the async world is a `janus.Queue` (or `asyncio.Queue` with `loop.call_soon_threadsafe`). All async tasks are gathered under a single `asyncio.TaskGroup` so cancellation propagates cleanly on shutdown.

---

## Project Structure

```
wifispy/
    main.py                 # Entry point, wiring, lifecycle
    interface_manager.py    # Monitor mode, channel hopping
    capture_engine.py       # Scapy sniff in thread, feeds async queue
    frame_parser.py         # Raw Scapy packet -> typed dataclasses
    state_aggregator.py     # In-memory model (APs, clients, associations, handshakes)
    alert_engine.py         # Deauth flood, evil twin, rogue AP detection
    pcap_exporter.py        # Filtered pcap writes via Scapy wrpcap
    cli_renderer.py         # Rich live tables and views
    command_handler.py      # User input, view switching, commands
    oui_lookup.py           # MAC vendor resolution
    models.py               # Dataclasses for all frame types and state objects
    exceptions.py           # Custom exception types
    config.py               # Configuration constants and defaults
    requirements.txt        # Python dependencies
```

---

## Dependencies

### Python Packages

- `scapy` -- packet capture, parsing, frame construction, pcap I/O
- `rich` -- CLI tables, live display, color formatting, tree views
- `manuf` -- OUI/vendor MAC lookup (alternative to manual IEEE database)
- `janus` -- sync/async queue bridge for Scapy thread communication
- `aioconsole` -- async stdin reading (optional, can use loop.add_reader)

### System Packages (WSL2)

- `aircrack-ng` -- airmon-ng for monitor mode management (deauth is handled natively by Scapy)
- `iw` / `wireless-tools` -- iwconfig for interface inspection and channel setting
- `usbipd-win` (Windows side) -- USB adapter passthrough to WSL2

### Hardware

- Monitor-mode capable USB WiFi adapter (e.g., Alfa AWUS036ACH with RTL8812AU chipset)
- WSL2 may require a custom kernel build to include the adapter's driver module

---

## Configuration Defaults (`config.py`)

| Parameter | Default | Description |
|---|---|---|
| `CHANNEL_HOP_INTERVAL` | 0.25 | Seconds between channel hops |
| `CHANNELS_24GHZ` | [1,6,11,2,3,4,5,7,8,9,10,12,13] | 2.4GHz scan order |
| `CHANNELS_5GHZ` | [36,40,44,48,52,56,60,64,100,...,165] | 5GHz scan order |
| `ENABLE_5GHZ` | False | Scan 5GHz channels |
| `RSSI_WINDOW_SIZE` | 10 | Samples for running RSSI average |
| `DEAUTH_THRESHOLD` | 10 | Deauth frames per window to trigger alert |
| `DEAUTH_WINDOW` | 10.0 | Sliding window in seconds for deauth detection |
| `ALERT_BUFFER_SIZE` | 100 | Max stored alerts |
| `PCAP_MAX_SIZE_MB` | 100 | Max pcap file size before rotation |
| `PCAP_MAX_FILES` | 5 | Number of rotating pcap files to keep |
| `RENDER_INTERVAL` | 1.0 | CLI refresh rate in seconds |
| `STALE_THRESHOLD` | 60.0 | Seconds before an entry is dimmed |
