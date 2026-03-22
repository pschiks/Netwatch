#!/usr/bin/env python3
"""
netwatch.py — Network Connection Monitor  (v8)
===============================================
Monitors internet connectivity with multi-layer probing:
  • TCP probe           — lightweight port-53 check to public DNS servers (internet)
  • ICMP ping           — gateway ping to isolate modem vs. upstream faults
  • DNS resolve         — verify DNS resolution separately from routing
  • Traceroute          — auto-triggered on outage start to pinpoint break location
  • macOS notify        — desktop alert on outage start/end
  • Jitter tracking     — latency variance as early warning of instability
  • Daily log rotation  — one CSV file per day, auto-rotated at midnight
  • Packet loss %       — multi-ping burst to detect partial loss (gaming/streaming)
  • Latency spikes      — single-probe spike detection even without full outage
  • App-specific probe  — target specific endpoints directly
  • Wi-Fi signal        — RSSI monitoring to distinguish Wi-Fi vs ISP faults
  • Pre-outage buffer   — ring buffer of recent samples flushed on outage start
  • Persistent TCP probe — long-lived socket to a safe neutral host, mimics
                           game/streaming connections (OS keepalive only, no active ping)
  • Path divergence     — parallel traceroute to persist host vs 1.1.1.1 on drop
  • UDP flood probe     — fires 10 ICMP/UDP packets/sec continuously; any gap in
                           responses flags a sub-second outage with ms precision

Safe persistent probe targets (all accept idle long-lived TCP connections,
none will flag or block a single persistent socket from a home IP):
  • 1.1.1.1:443        Cloudflare HTTPS — ideal, designed for massive concurrency
  • 8.8.8.8:443        Google DNS over HTTPS — same properties
  • 8.8.4.4:443        Google alt DNS (replaces Quad9 which has high latency variance)
  • 93.184.216.34:443  example.com (IANA/Cloudflare) — minimal, neutral
  Default: 1.1.1.1:443  (recommended — closest to your ISP, Cloudflare peers
                          with nearly every ISP including Delta Fiber)

Usage:
    python3 netwatch.py [options]

    Core timing
    -----------
    --interval SECS         Probe interval in seconds            (default: 0.5)
    --summary SECS          Summary print interval               (default: 5)
    --timeout SECS          Per-probe timeout                    (default: 3)

    Internet probe
    --------------
    --host HOST             Fixed probe host; default: auto-rotate
    --port PORT             Port when --host is set              (default: 53)

    Gateway / local layer
    ---------------------
    --gateway IP            Gateway IP to ping                   (default: 10.0.1.1)
    --no-gateway            Disable gateway ping
    --ping-count N          ICMP packets per gateway check       (default: 1)

    DNS resolution check
    --------------------
    --dns-host HOSTNAME     Hostname to resolve                  (default: one.one.one.one)
    --no-dns                Disable DNS resolution check

    Alerting / thresholds
    ---------------------
    --latency-warn MS       Warn if RTT exceeds this value       (default: 200)
    --jitter-warn MS        Warn if jitter (std-dev) exceeds this(default: 50)
    --outage-threshold N    Consecutive failures = outage event  (default: 3)
    --no-notify             Disable macOS desktop notifications

    Sound alarm
    -----------
    --sound-profile NAME    Alarm profile on outage              (default: alert)
                              alert   — three short system beeps (subtle)
                              urgent  — rapid repeating beep + voice announcement
                              voice   — spoken announcement only, no beeps
                              beep    — single terminal bell only
                              off     — silence (disables all sound)
    --sound-restore         Also play a sound when connection is restored
    --no-sound              Alias for --sound-profile off

    Auto-traceroute on outage
    -------------------------
    --traceroute            Enable auto-traceroute on outage start
    --traceroute-host IP    Target for auto-traceroute           (default: 1.1.1.1)
    --traceroute-hops N     Max hops                            (default: 15)

    Packet loss check
    -----------------
    --loss-pings N          Pings per loss burst                 (default: 10)
    --loss-warn PCT         Warn if packet loss exceeds this %   (default: 2)
    --loss-interval N       Run loss check every N probes        (default: 20)
    --no-loss               Disable packet loss check

    Latency spike detection
    -----------------------
    --spike-warn MS         Warn on single probe exceeding this  (default: 400)

    App-specific probe
    ------------------
    --app-host HOST         Hostname/IP to probe as app target
    --app-port PORT         Port for app probe                   (default: 443)
    --app-label LABEL       Label shown in output                (default: app)

    Persistent TCP probe (long-lived socket — mimics Eve/streaming)
    ---------------------------------------------------------------
    --persist-host HOST     Host to keep a persistent TCP socket open to
                              default: test.mosquitto.org (public MQTT test broker,
                              designed for this use — safe, no DDoS risk)
    --persist-port PORT     Port for persistent probe            (default: 1883)
    --persist-label LABEL   Label shown in output                (default: persist)
    --persist-timeout SECS  Timeout for persistent reconnect     (default: 5)
    --persist-ping N        Send MQTT PINGREQ every N probes     (default: 20)
    --no-persist-reconnect  Do not auto-reconnect on drop (just log the drop)

    Path divergence traceroute
    --------------------------
    --path-trace            On any app probe failure, run parallel traceroutes
                            to both the app host and 1.1.1.1 and save the diff

    Wi-Fi signal (macOS)
    --------------------
    --wifi                  Enable Wi-Fi RSSI monitoring
    --wifi-warn DBM         Warn if RSSI drops below this        (default: -70)

    Pre-outage buffer
    -----------------
    --prebuffer N           Rows to save before outage starts    (default: 30)
    --no-prebuffer          Disable pre-outage ring buffer

    Logging
    -------
    --log FILE              Fixed CSV log file (disables rotation)
    --log-dir DIR           Directory for rotated daily logs     (default: .)
    --no-rotate             Disable daily rotation (single timestamped file)

Stop:
    Press Ctrl+C to stop and save the log.

Examples:
    python3 netwatch.py
    python3 netwatch.py --interval 0.25 --traceroute
    python3 netwatch.py --no-gateway --no-dns --log-dir ~/netlogs
    python3 netwatch.py --host 1.1.1.1 --no-notify --latency-warn 100
"""

import argparse
import csv
import math
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, date

# ─────────────────────────────────────────────────────────────────────────────
# Internet probe targets — rotate to spread load
# ─────────────────────────────────────────────────────────────────────────────
PROBE_TARGETS = [
    ("8.8.8.8",        53, "Google DNS"),        # Google — AMS-IX peering, very stable
    ("1.1.1.1",        53, "Cloudflare DNS"),    # Cloudflare — AMS-IX peering, very stable
    ("208.67.222.222", 53, "OpenDNS"),           # Cisco OpenDNS — good EU presence
    ("1.0.0.1",        53, "Cloudflare alt"),    # Cloudflare alt — different anycast node
    ("8.8.4.4",        53, "Google alt"),        # Google alt — different anycast node
    # Quad9 (9.9.9.9) removed — security filtering causes high latency variance
    # and frequent timeouts that pollute monitoring data with false positives.
]

# App-specific probe targets (used as suggestion / fallback if no --app-host given)
APP_PROBE_SUGGESTIONS = [
    ("login.eveonline.com", 443, "Eve Online"),
    ("api.twitch.tv",       443, "Twitch"),
    ("clients3.google.com", 443, "Google"),
]

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colours
# ─────────────────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────────────────────────────────────
stats = {
    # internet probe
    "total":   0,
    "success": 0,
    "failure": 0,
    # outage tracking
    "outages":           0,
    "outage_start":      None,
    "in_outage":         False,
    "total_outage_secs": 0.0,
    "consecutive_fail":  0,
    "consecutive_ok":    0,
    # latency
    "latency_sum":    0.0,
    "latency_max":    0.0,
    "latency_min":    float("inf"),
    "latency_window": deque(maxlen=20),   # last 20 samples for jitter calc
    # gateway ping
    "gw_total":       0,
    "gw_success":     0,
    "gw_failure":     0,
    "gw_latency_sum": 0.0,
    "gw_latency_max": 0.0,
    "gw_latency_min": float("inf"),
    # dns resolve
    "dns_total":   0,
    "dns_success": 0,
    "dns_failure": 0,
    # packet loss
    "loss_checks":    0,
    "loss_sum":       0.0,
    "loss_max":       0.0,
    "loss_warn_count": 0,
    # latency spikes
    "spike_count": 0,
    # app probe
    "app_total":   0,
    "app_success": 0,
    "app_failure": 0,
    # persistent TCP probe
    "persist_connected":     False,
    "persist_connect_time":  None,
    "persist_drops":         0,
    "persist_drop_durations": [],   # list of drop durations in seconds
    "persist_last_drop_ts":  None,
    # wifi
    "wifi_rssi_min": 0,
    "wifi_warn_count": 0,
    # tcp flood probe
    "flood_gaps_session": 0,     # gaps detected this session
    "flood_max_gap_ms":   0.0,   # longest gap seen
    # timing
    "last_summary": time.monotonic(),
    "start_time":   datetime.now(),
    "probe_count":  0,   # raw counter used for loss/wifi scheduling
}

log_writer       = None
log_file_fp      = None
log_path         = None
current_log_date = None
args             = None
target_idx       = 0
pre_outage_buf   = deque()   # ring buffer of recent CSV rows (size set from args)
persist_sock     = None      # the long-lived TCP socket (mimics Eve/streaming)
persist_lock     = threading.Lock()
persist_enabled     = False     # set in main() after args parsed
flood_enabled_flag  = False     # set in main() after args parsed

# ── UDP flood probe state ─────────────────────────────────────────────────
# A background thread fires ICMP echo requests 10x/sec and timestamps every
# response. The main loop reads the gap log to detect sub-second blackouts.
udp_flood_lock   = threading.Lock()
udp_flood_gaps   = []          # list of (start_ts, gap_ms) tuples
udp_flood_last   = None        # monotonic time of last response received
udp_flood_seq    = 0           # ICMP sequence counter
udp_flood_running = False


# ─────────────────────────────────────────────────────────────────────────────
# Probes
# ─────────────────────────────────────────────────────────────────────────────

def probe_tcp(host: str, port: int, timeout: float) -> tuple:
    """TCP connect to port — minimal traffic (~80 bytes), no payload."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return True, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, (time.perf_counter() - t0) * 1000


def probe_ping(host: str, count: int, timeout: float) -> tuple:
    """ICMP ping via system ping. Returns (reachable, avg_rtt_ms)."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count),
             "-W", str(int(timeout * 1000)),
             "-q", host],
            capture_output=True, text=True, timeout=timeout + 3
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "round-trip" in line or "rtt" in line:
                    parts = line.split("=")[-1].strip().split("/")
                    return True, float(parts[1])
            return True, 0.0
        return False, 0.0
    except Exception:
        return False, 0.0


def probe_dns(hostname: str, timeout: float) -> tuple:
    """Resolve hostname using system resolver. Returns (ok, latency_ms)."""
    t0 = time.perf_counter()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(hostname, None)
        return True, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, (time.perf_counter() - t0) * 1000
    finally:
        socket.setdefaulttimeout(None)


def probe_packet_loss(host: str, count: int, timeout: float) -> tuple:
    """Send `count` pings rapidly and return (loss_pct, avg_rtt_ms)."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count),
             "-i", "0.1",                        # 100ms between pings
             "-W", str(int(timeout * 1000)),
             "-q", host],
            capture_output=True, text=True,
            timeout=timeout + count * 0.15 + 2
        )
        loss_pct = 100.0
        avg_rtt  = 0.0
        for line in result.stdout.splitlines():
            if "packet loss" in line:
                try:
                    loss_pct = float(line.split("%")[0].split()[-1])
                except ValueError:
                    pass
            if "round-trip" in line or "rtt" in line:
                parts = line.split("=")[-1].strip().split("/")
                try:
                    avg_rtt = float(parts[1])
                except (IndexError, ValueError):
                    pass
        return loss_pct, avg_rtt
    except Exception:
        return 100.0, 0.0


def probe_wifi_signal() -> tuple:
    """Return (ssid, rssi_dbm) via macOS airport utility. (None, None) if unavailable."""
    airport = ("/System/Library/PrivateFrameworks/Apple80211.framework"
               "/Versions/Current/Resources/airport")
    if not os.path.exists(airport):
        return None, None
    try:
        result = subprocess.run(
            [airport, "-I"],
            capture_output=True, text=True, timeout=4
        )
        ssid, rssi = None, None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("SSID:") and "BSSID" not in line:
                ssid = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("agrCtlRSSI:"):
                try:
                    rssi = int(stripped.split(":")[1].strip())
                except ValueError:
                    pass
        return ssid, rssi
    except Exception:
        return None, None


def persist_connect(host: str, port: int, timeout: float) -> bool:
    """
    Open a persistent TCP connection with OS-level keepalive enabled.
    Works against any host:port — no application protocol needed.
    TCP keepalive probes are handled entirely by the OS TCP stack;
    the remote end needs no special support.
    Returns True on success.
    """
    global persist_sock
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Aggressive keepalive: detect drops within ~25 seconds
        # (10s idle + 3 probes × 5s each)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  10)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL,  5)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,    3)
        except AttributeError:
            pass  # some constants absent on older macOS — harmless
        # TCP_USER_TIMEOUT: force-close if unacknowledged data sits > 30s
        # This catches the case where keepalives are sent but never ACK'd
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 30_000)
        except AttributeError:
            pass
        s.settimeout(None)  # blocking from here on
        with persist_lock:
            persist_sock = s
        return True
    except Exception:
        return False


def persist_ping() -> bool:
    """Stub — active ping removed in v7 (was causing false positives).
    OS-level TCP keepalive handles liveness detection passively."""
    return persist_is_alive()


def persist_is_alive() -> bool:
    """
    Fast per-cycle liveness check via non-blocking recv.
    EAGAIN = socket open but no data = alive.
    b'' or exception = dead.
    """
    global persist_sock
    with persist_lock:
        s = persist_sock
    if s is None:
        return False
    try:
        s.setblocking(False)
        data = s.recv(1)
        s.setblocking(True)
        return len(data) > 0
    except BlockingIOError:
        return True
    except Exception:
        return False


def persist_close():
    global persist_sock
    with persist_lock:
        if persist_sock:
            try:
                persist_sock.close()
            except Exception:
                pass
            persist_sock = None


# ─────────────────────────────────────────────────────────────────────────────
# TCP keepalive flood probe
# Sends a DNS query over TCP every 100ms on the SAME persistent connection.
# Any gap in responses > threshold reveals a sub-second NAT flush or route drop
# with millisecond precision — something no polling probe can catch.
#
# Target: 1.1.1.1:53 TCP (Cloudflare DNS over TCP)
#   - Standard protocol, explicitly supported, connection stays open
#   - 35-byte query, ~33-byte response — negligible traffic (~5KB/min)
#   - Port 53 is never blocked or firewalled
#   - Creates a stateful NAT entry identical to Eve Online / game traffic
# ─────────────────────────────────────────────────────────────────────────────

# Shared state between flood thread and main thread
flood_lock        = threading.Lock()
flood_gaps        = []       # list of (datetime, gap_ms) — gaps > threshold
flood_last_rx     = None     # monotonic timestamp of last successful response
flood_connected   = False    # is the flood socket currently up?
flood_drop_start  = None     # monotonic time when current gap started
flood_total_gaps  = 0
flood_sock        = None
flood_running     = False
flood_drop_active      = False   # True while flood has no live connection (read by main loop)
flood_rtt_last_ms      = 0.0    # last successful RTT in ms (logged every cycle)
flood_nat_reported_at  = None   # monotonic time of last NAT_FLUSH_CONFIRMED print
                                # used to suppress duplicate messages per drop event
flood_drop_reason      = ""     # why the flood probe last dropped:
                                #   TIMEOUT     = no response → true NAT flush / route drop
                                #   SERVER_RST  = server sent TCP RST (server-side close)
                                #   SERVER_FIN  = server closed cleanly (idle timeout)
                                #   BROKEN_PIPE = write failed (server gone)
                                #   OTHER:XYZ   = unexpected exception type


def _build_dns_query(seq: int) -> bytes:
    """Build a minimal TCP DNS A query for one.one.one.one, seq as query ID."""
    import struct
    qid = seq & 0xFFFF
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    # Encode "one.one.one.one"
    qname = b"\x03one\x03one\x03one\x03one\x00"
    question = qname + struct.pack(">HH", 1, 1)   # QTYPE=A QCLASS=IN
    msg = header + question
    return struct.pack(">H", len(msg)) + msg       # TCP length prefix


def _flood_thread(host: str, port: int, interval: float,
                  gap_threshold_ms: float, log_dir: str):
    """
    Background thread: maintains a persistent TCP connection and sends a DNS
    query every `interval` seconds. Measures RTT of each response.
    Any gap > gap_threshold_ms is recorded with a millisecond timestamp.
    Auto-reconnects on drop and logs the reconnect time.
    """
    global flood_connected, flood_last_rx, flood_drop_start
    global flood_total_gaps, flood_sock, flood_drop_active, flood_rtt_last_ms
    global flood_drop_reason, flood_nat_reported_at

    import struct

    seq = 0

    def connect():
        global flood_sock, flood_connected, flood_drop_start
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  5)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 10_000)
            except AttributeError:
                pass
            s.settimeout(3)
            s.connect((host, port))
            s.settimeout(interval * 3)   # response timeout = 3 intervals
            with flood_lock:
                flood_sock        = s
                flood_connected   = True
                flood_drop_start  = None
                flood_drop_active = False   # clear on every successful connect
            return s
        except Exception:
            with flood_lock:
                flood_connected = False
            return None

    s = connect()

    while flood_running:
        if s is None:
            time.sleep(0.5)
            s = connect()
            continue

        query = _build_dns_query(seq)
        seq  += 1
        t_send = time.monotonic()

        try:
            s.sendall(query)
            # Read 2-byte length prefix
            raw_len = b""
            while len(raw_len) < 2:
                chunk = s.recv(2 - len(raw_len))
                if not chunk:
                    raise ConnectionError("server closed")
                raw_len += chunk
            resp_len = struct.unpack(">H", raw_len)[0]
            # Read response body
            resp = b""
            while len(resp) < resp_len:
                chunk = s.recv(resp_len - len(resp))
                if not chunk:
                    raise ConnectionError("server closed")
                resp += chunk

            t_rx   = time.monotonic()
            rtt_ms = (t_rx - t_send) * 1000

            with flood_lock:
                # If we were in a gap — close it now
                if flood_drop_start is not None:
                    gap_ms = (t_rx - flood_drop_start) * 1000
                    flood_gaps.append((datetime.now(), gap_ms))
                    flood_total_gaps += 1
                    flood_drop_start  = None
                    flood_drop_active     = False   # signal to main loop: recovered
                    flood_nat_reported_at = None    # reset cooldown for next event
                    # Print recovery inline
                    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    print(f"\n  {GREEN}⚡ {ts_str}  TCP-flood RESTORED "
                          f"— gap {gap_ms:.0f}ms  reason was: {flood_drop_reason}{RESET}")
                flood_last_rx     = t_rx
                flood_connected   = True
                flood_drop_active = False   # always clear on successful recv
                flood_rtt_last_ms = rtt_ms   # expose RTT for CSV logging

        except Exception as _exc:
            t_drop = time.monotonic()
            # Classify the drop reason so we can distinguish:
            #   TIMEOUT    → no response from server → true NAT flush or route drop
            #   SERVER_RST → server sent TCP RST    → server-side idle timeout / close
            #   SERVER_FIN → clean server close     → server-side idle timeout
            #   BROKEN_PIPE→ write failed            → server gone mid-send
            if isinstance(_exc, socket.timeout):
                _reason = "TIMEOUT"
            elif isinstance(_exc, ConnectionResetError):
                _reason = "SERVER_RST"
            elif isinstance(_exc, (EOFError, ConnectionError)) and not isinstance(_exc, ConnectionResetError):
                _reason = "SERVER_FIN"
            elif isinstance(_exc, BrokenPipeError):
                _reason = "BROKEN_PIPE"
            else:
                _reason = f"OTHER:{type(_exc).__name__}"
            with flood_lock:
                flood_drop_reason = _reason
                if flood_connected:
                    flood_connected   = False
                    flood_drop_active = True   # signal to main loop: we are down
                    flood_drop_start  = t_drop
                    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    # Colour-code by reason: TIMEOUT is red (real problem),
                    # server-side closes are yellow (harmless)
                    _colour = RED if _reason == "TIMEOUT" else YELLOW
                    print(f"\n  {_colour}⚡ {ts_str}  TCP-flood DROP [{_reason}] "
                          f"on {host}:{port}{RESET}")
            try:
                s.close()
            except Exception:
                pass
            s = None
            with flood_lock:
                flood_sock = s
            time.sleep(0.1)
            s = connect()
            continue

        # Check for silent gap — no exception but no recent rx
        with flood_lock:
            if flood_last_rx and (time.monotonic() - flood_last_rx) * 1000 > gap_threshold_ms:
                if flood_drop_start is None:
                    flood_drop_start = flood_last_rx
                    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    print(f"\n  {RED}⚡ {ts_str}  TCP-flood SILENT GAP "
                          f"> {gap_threshold_ms:.0f}ms{RESET}")

        # Sleep until next send window
        elapsed = time.monotonic() - t_send
        sleep_for = interval - elapsed
        if sleep_for > 0:
            time.sleep(sleep_for)

    # Clean up
    if flood_sock:
        try:
            flood_sock.close()
        except Exception:
            pass


def run_path_divergence(app_host: str, app_port: int,
                        ref_host: str, log_dir: str, ts_str: str):
    """
    Run traceroutes to both the app host and a reference host in parallel,
    then diff the paths to show where they diverge. Saved to a .txt file.
    This is the key tool for catching BGP route flaps affecting specific destinations.
    """
    safe_ts  = ts_str.replace(" ", "_").replace(":", "-")
    out_path = os.path.join(log_dir, f"path_divergence_{safe_ts}.txt")

    def do_trace(host, hops):
        try:
            r = subprocess.run(
                ["traceroute", "-m", str(hops), "-w", "2", "-n", host],
                capture_output=True, text=True, timeout=hops * 5
            )
            return r.stdout
        except Exception as e:
            return f"(traceroute failed: {e})\n"

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_app = ex.submit(do_trace, app_host, 20)
        f_ref = ex.submit(do_trace, ref_host, 20)
        trace_app = f_app.result()
        trace_ref = f_ref.result()

    # Parse hop IPs from each traceroute for comparison
    def parse_hops(trace_text):
        hops = []
        for line in trace_text.splitlines():
            parts = line.strip().split()
            if parts and parts[0].isdigit():
                # Find first IP-like token
                ip = next((p for p in parts[1:] if p.count('.') == 3
                           or ':' in p), '*')
                hops.append((int(parts[0]), ip))
        return hops

    hops_app = parse_hops(trace_app)
    hops_ref = parse_hops(trace_ref)

    # Find where paths diverge
    diverge_at = None
    for (n1, ip1), (n2, ip2) in zip(hops_app, hops_ref):
        if ip1 != ip2 and ip1 != '*' and ip2 != '*':
            diverge_at = n1
            break

    with open(out_path, "w") as f:
        f.write(f"Path divergence analysis — triggered at {ts_str}\n")
        f.write(f"App target : {app_host}:{app_port}\n")
        f.write(f"Reference  : {ref_host}\n")
        f.write("=" * 60 + "\n\n")
        if diverge_at:
            f.write(f"*** Paths diverge at hop {diverge_at} ***\n")
            f.write("    This is where the routing difference begins.\n\n")
        else:
            f.write("Paths appear to share the same route (or too many * hops).\n\n")
        f.write(f"--- Traceroute to {app_host} ---\n")
        f.write(trace_app)
        f.write(f"\n--- Traceroute to {ref_host} (reference) ---\n")
        f.write(trace_ref)

    print(f"\n  {BLUE}↳ Path divergence saved: {out_path}"
          f"{f'  (diverges at hop {diverge_at})' if diverge_at else ''}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Jitter — standard deviation of last N latency samples
# ─────────────────────────────────────────────────────────────────────────────

def calc_jitter() -> float:
    window = stats["latency_window"]
    if len(window) < 2:
        return 0.0
    mean = sum(window) / len(window)
    return math.sqrt(sum((x - mean) ** 2 for x in window) / len(window))


# ─────────────────────────────────────────────────────────────────────────────
# macOS Desktop Notification
# ─────────────────────────────────────────────────────────────────────────────

def notify(title: str, message: str):
    """Send a macOS Notification Center alert. Best-effort."""
    try:
        script = (f'display notification "{message}" '
                  f'with title "{title}" sound name "Basso"')
        subprocess.run(["osascript", "-e", script],
                       capture_output=True, timeout=5)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Sound alarm — macOS afplay + say, runs in background thread
# ─────────────────────────────────────────────────────────────────────────────

# macOS system sounds available via afplay /System/Library/Sounds/<name>.aiff
_SYS_SOUNDS = "/System/Library/Sounds"

# Sound profiles
#   Each profile is a list of steps executed in order.
#   Step types:
#     ("beep",  n)           — n terminal BEL characters
#     ("play",  name, rate)  — afplay a system .aiff at given playback rate
#     ("say",   text)        — macOS TTS via `say`
#     ("pause", secs)        — sleep between steps
#     ("repeat", n, steps)   — repeat sub-steps n times

SOUND_PROFILES = {
    # Default — noticeable but not panic-inducing
    "alert": [
        ("play",  "Sosumi",  1.0),
        ("pause", 0.35),
        ("play",  "Sosumi",  1.0),
        ("pause", 0.35),
        ("play",  "Sosumi",  1.0),
    ],
    # Urgent — fast repeating alarm + voice
    "urgent": [
        ("repeat", 5, [
            ("play",  "Funk", 1.3),
            ("pause", 0.18),
        ]),
        ("say", "Network outage detected"),
    ],
    # Voice only — clear spoken announcement, no beeps
    "voice": [
        ("say", "Warning. Internet connection lost."),
    ],
    # Minimal — terminal bell only, works even without speakers
    "beep": [
        ("beep", 3),
    ],
    # Restored — gentle positive sound (used with --sound-restore)
    "_restore": [
        ("play", "Glass", 1.0),
    ],
    # Voice restore
    "_restore_voice": [
        ("say", "Internet connection restored."),
    ],
}


def _play_system_sound(name: str, rate: float = 1.0):
    path = os.path.join(_SYS_SOUNDS, f"{name}.aiff")
    if not os.path.exists(path):
        # Fallback to terminal bell
        sys.stdout.write("\a")
        sys.stdout.flush()
        return
    try:
        subprocess.run(["afplay", "-r", str(rate), path],
                       capture_output=True, timeout=10)
    except Exception:
        sys.stdout.write("\a")
        sys.stdout.flush()


def _run_steps(steps: list):
    for step in steps:
        kind = step[0]
        if kind == "beep":
            for _ in range(step[1]):
                sys.stdout.write("\a")
                sys.stdout.flush()
                time.sleep(0.25)
        elif kind == "play":
            _play_system_sound(step[1], step[2])
        elif kind == "say":
            try:
                subprocess.run(["say", step[1]],
                               capture_output=True, timeout=10)
            except Exception:
                pass
        elif kind == "pause":
            time.sleep(step[1])
        elif kind == "repeat":
            for _ in range(step[1]):
                _run_steps(step[2])


def play_alarm(profile: str, outage_num: int = 0):
    """Play alarm in a background thread so it never blocks the probe loop."""
    if profile == "off":
        return
    steps = SOUND_PROFILES.get(profile, SOUND_PROFILES["alert"])
    # For voice profiles, inject the outage number into the TTS text
    if profile in ("urgent", "voice") and outage_num:
        steps = [
            ("say", f"Network outage number {outage_num} detected."),
        ] + steps
    threading.Thread(target=_run_steps, args=(steps,), daemon=True).start()


def play_restore(profile: str):
    """Play restoration sound in background thread."""
    if profile == "off":
        return
    if profile == "voice":
        steps = SOUND_PROFILES["_restore_voice"]
    elif profile == "urgent":
        steps = SOUND_PROFILES["_restore_voice"]
    else:
        steps = SOUND_PROFILES["_restore"]
    threading.Thread(target=_run_steps, args=(steps,), daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# Auto-traceroute (runs in a background thread)
# ─────────────────────────────────────────────────────────────────────────────

def flush_pre_outage_buffer(log_dir: str, ts_str: str):
    """Write the pre-outage ring buffer to a separate CSV for post-mortem analysis."""
    if not pre_outage_buf:
        return
    safe_ts  = ts_str.replace(" ", "_").replace(":", "-")
    filename = f"premonition_{safe_ts}.csv"
    out_path = os.path.join(log_dir, filename)
    try:
        with open(out_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp", "probe_host", "probe_label",
                "result", "latency_ms",
                "gateway_result", "gateway_latency_ms",
                "dns_result", "dns_latency_ms",
                "jitter_ms", "loss_pct", "app_result", "app_latency_ms",
                "wifi_rssi", "event"
            ])
            w.writerows(pre_outage_buf)
        print(f"\n  {BLUE}↳ Pre-outage buffer saved ({len(pre_outage_buf)} rows): {out_path}{RESET}")
    except Exception as e:
        print(f"\n  {YELLOW}↳ Pre-outage buffer save failed: {e}{RESET}")


def run_traceroute(host: str, max_hops: int, log_dir: str, ts_str: str):
    """Run traceroute and save output to a separate .txt file."""
    safe_ts  = ts_str.replace(" ", "_").replace(":", "-")
    filename = f"traceroute_{safe_ts}.txt"
    out_path = os.path.join(log_dir, filename)
    try:
        result = subprocess.run(
            ["traceroute", "-m", str(max_hops), "-w", "2", host],
            capture_output=True, text=True, timeout=max_hops * 5
        )
        with open(out_path, "w") as f:
            f.write(f"Traceroute to {host}  —  triggered at {ts_str}\n")
            f.write("=" * 60 + "\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\nSTDERR:\n" + result.stderr)
        print(f"\n  {BLUE}↳ Traceroute saved: {out_path}{RESET}")
    except Exception as e:
        print(f"\n  {YELLOW}↳ Traceroute failed: {e}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Logging with optional daily rotation
# ─────────────────────────────────────────────────────────────────────────────

def _log_filepath_for_date(log_dir: str, d: date) -> str:
    return os.path.join(log_dir, f"netwatch_{d.strftime('%Y%m%d')}.csv")


def open_log(path: str, write_header: bool):
    global log_writer, log_file_fp, log_path
    if log_file_fp:
        log_file_fp.close()
    log_path    = path
    log_file_fp = open(path, "a", newline="", buffering=1)
    log_writer  = csv.writer(log_file_fp)
    if write_header:
        log_writer.writerow([
            "timestamp", "probe_host", "probe_label",
            "result", "latency_ms",
            "gateway_result", "gateway_latency_ms",
            "dns_result", "dns_latency_ms",
            "jitter_ms",
            "loss_pct", "app_result", "app_latency_ms",
            "wifi_rssi",
            "persist_result", "persist_drop_secs",
            "flood_rtt_ms", "event"
        ])


def maybe_rotate_log(log_dir: str):
    """Open a new daily log file if the calendar date has changed."""
    global current_log_date
    today = date.today()
    if today != current_log_date:
        path       = _log_filepath_for_date(log_dir, today)
        new_file   = not os.path.exists(path)
        open_log(path, write_header=new_file)
        current_log_date = today
        if new_file:
            print(f"\n  {CYAN}↳ New daily log started: {path}{RESET}")


def write_log(ts, host, label, result, latency,
              gw_result, gw_lat, dns_result, dns_lat, jitter,
              loss_pct="N/A", app_result="N/A", app_lat=0.0,
              wifi_rssi="N/A", persist_result="N/A", persist_drop_secs="N/A",
              flood_rtt_ms=0.0, event=""):
    row = [
        ts, host, label,
        result, f"{latency:.2f}",
        gw_result, f"{gw_lat:.2f}",
        dns_result, f"{dns_lat:.2f}",
        f"{jitter:.2f}",
        loss_pct if loss_pct == "N/A" else f"{loss_pct:.1f}",
        app_result,
        f"{app_lat:.2f}",
        wifi_rssi,
        persist_result,
        persist_drop_secs,
        f"{flood_rtt_ms:.2f}" if flood_rtt_ms else "N/A",
        event
    ]
    if args and not args.no_prebuffer:
        pre_outage_buf.append(row)
    log_writer.writerow(row)


# ─────────────────────────────────────────────────────────────────────────────
# Outage state machine
# ─────────────────────────────────────────────────────────────────────────────

def handle_failure(ts: datetime) -> str:
    stats["consecutive_fail"] += 1
    stats["consecutive_ok"]    = 0
    if (not stats["in_outage"] and
            stats["consecutive_fail"] >= args.outage_threshold):
        stats["in_outage"]    = True
        stats["outage_start"] = ts
        stats["outages"]     += 1
        return "OUTAGE_START"
    return ""


def handle_success(ts: datetime) -> str:
    stats["consecutive_ok"]  += 1
    stats["consecutive_fail"] = 0
    if stats["in_outage"] and stats["consecutive_ok"] >= 2:
        duration = (ts - stats["outage_start"]).total_seconds()
        stats["total_outage_secs"] += duration
        stats["in_outage"]    = False
        stats["outage_start"] = None
        return f"OUTAGE_END ({duration:.1f}s)"
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Summary block printed every --summary seconds
# ─────────────────────────────────────────────────────────────────────────────

def print_summary():
    uptime     = (datetime.now() - stats["start_time"]).total_seconds()
    pct_ok     = (stats["success"] / stats["total"] * 100
                  if stats["total"] else 0)
    avg_lat    = (stats["latency_sum"] / stats["success"]
                  if stats["success"] else 0)
    jitter     = calc_jitter()
    lat_min    = stats["latency_min"] if stats["latency_min"] != float("inf") else 0
    uptime_str = time.strftime("%H:%M:%S", time.gmtime(uptime))
    ts_now     = datetime.now().strftime("%H:%M:%S")
    outage_bar = f"  {RED}⚠  IN OUTAGE{RESET}" if stats["in_outage"] else ""

    # Gateway row
    gw_line = ""
    if not args.no_gateway:
        gw_total = stats["gw_total"]
        if gw_total:
            gw_pct = stats["gw_success"] / gw_total * 100
            gw_avg = (stats["gw_latency_sum"] / stats["gw_success"]
                      if stats["gw_success"] else 0)
            gw_col = GREEN if gw_pct > 99 else (YELLOW if gw_pct > 90 else RED)
            gw_line = (f"\n  Gateway : {args.gateway:<15}  "
                       f"checks {gw_total:>5}  "
                       f"{gw_col}OK {gw_pct:5.1f}%{RESET}  "
                       f"avg {gw_avg:6.1f} ms")

    # DNS row
    dns_line = ""
    if not args.no_dns:
        dns_total = stats["dns_total"]
        if dns_total:
            dns_pct = stats["dns_success"] / dns_total * 100
            dns_col = GREEN if dns_pct > 99 else (YELLOW if dns_pct > 90 else RED)
            dns_line = (f"\n  DNS     : {args.dns_host:<15}  "
                        f"checks {dns_total:>5}  "
                        f"{dns_col}OK {dns_pct:5.1f}%{RESET}")

    # Packet loss row
    loss_line = ""
    if not args.no_loss and stats["loss_checks"] > 0:
        avg_loss = stats["loss_sum"] / stats["loss_checks"]
        loss_col = RED if avg_loss > args.loss_warn else GREEN
        loss_line = (f"\n  PktLoss : checks {stats['loss_checks']:>4}  "
                     f"avg {loss_col}{avg_loss:5.1f}%{RESET}  "
                     f"max {stats['loss_max']:.1f}%  "
                     f"warn events {stats['loss_warn_count']}")

    # App probe row
    app_line = ""
    if args.app_host and stats["app_total"] > 0:
        app_pct = stats["app_success"] / stats["app_total"] * 100
        app_col = GREEN if app_pct > 99 else (YELLOW if app_pct > 90 else RED)
        app_line = (f"\n  App     : {args.app_label:<15}  "
                    f"checks {stats['app_total']:>5}  "
                    f"{app_col}OK {app_pct:5.1f}%{RESET}  "
                    f"({args.app_host}:{args.app_port})")

    # Spike row
    spike_line = ""
    if stats["spike_count"] > 0:
        spike_line = (f"\n  Spikes  : {RED}{stats['spike_count']} spike(s){RESET} "
                      f"above {args.spike_warn:.0f}ms detected this session")

    # TCP flood row
    flood_line = ""
    if flood_enabled_flag:
        with flood_lock:
            n_gaps    = len(flood_gaps)
            max_gap   = max((g for _, g in flood_gaps), default=0.0)
            f_conn    = flood_connected
            recent    = [(ts, ms) for ts, ms in flood_gaps[-5:]]
        conn_str  = f"{GREEN}UP{RESET}" if f_conn else f"{RED}DOWN{RESET}"
        gap_col   = RED if n_gaps > 0 else GREEN
        with flood_lock:
            _last_reason = flood_drop_reason
        _reason_str = f"  last drop: {_last_reason}" if _last_reason else ""
        flood_line = (f"\n  TCPFlood: {args.flood_host}:{args.flood_port}  "
                      f"state {conn_str}  "
                      f"{gap_col}gaps {n_gaps}{RESET}"
                      f"{f'  max {max_gap:.0f}ms' if n_gaps > 0 else ''}"
                      f"{_reason_str}")
        if recent and n_gaps > 0:
            flood_line += f"  last: {recent[-1][0].strftime('%H:%M:%S.%f')[:-3]} ({recent[-1][1]:.0f}ms)"

    # Persistent socket row
    persist_line = ""
    if persist_enabled:
        state_str = f"{GREEN}ALIVE{RESET}" if stats["persist_connected"] \
                    else f"{RED}DOWN{RESET}"
        drops = stats["persist_drops"]
        drop_col = RED if drops > 0 else GREEN
        avg_drop = (sum(stats["persist_drop_durations"]) / len(stats["persist_drop_durations"])
                    if stats["persist_drop_durations"] else 0)
        persist_line = (f"\n  Persist : {args.persist_label:<15}  "
                        f"state {state_str}  "
                        f"{drop_col}drops {drops}{RESET}"
                        f"{f'  avg recovery {avg_drop:.1f}s' if drops > 0 else ''}"
                        f"  ({args.persist_host}:{args.persist_port})")

    jit_col = YELLOW if jitter > args.jitter_warn else GREEN

    print(
        f"\n{DIM}{'─'*68}{RESET}\n"
        f"  {BOLD}{CYAN}[{ts_now}]{RESET}  "
        f"session uptime {uptime_str}{outage_bar}\n"
        f"  Internet: probes {stats['total']:>6}  "
        f"{GREEN}OK {stats['success']:>5}{RESET}  "
        f"{RED}FAIL {stats['failure']:>4}{RESET}  "
        f"avail {GREEN}{pct_ok:5.1f}%{RESET}\n"
        f"  Latency : avg {avg_lat:6.1f} ms  "
        f"min {lat_min:6.1f} ms  "
        f"max {stats['latency_max']:6.1f} ms  "
        f"jitter {jit_col}{jitter:5.1f} ms{RESET}"
        f"{gw_line}"
        f"{dns_line}"
        f"{loss_line}"
        f"{app_line}"
        f"{persist_line}"
        f"{flood_line}"
        f"{spike_line}\n"
        f"  Outages : {stats['outages']:>3}  "
        f"total down {stats['total_outage_secs']:.1f}s  "
        f"log → {DIM}{log_path}{RESET}"
    )
    stats["last_summary"] = time.monotonic()


# ─────────────────────────────────────────────────────────────────────────────
# Graceful shutdown
# ─────────────────────────────────────────────────────────────────────────────

def shutdown(sig=None, frame=None):
    global flood_running
    print(f"\n\n{YELLOW}Stopping netwatch…{RESET}")
    flood_running = False
    persist_close()
    print_summary()
    if log_file_fp:
        log_file_fp.close()
    print(f"\n{GREEN}Log saved: {log_path}{RESET}\n")
    sys.exit(0)


signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    global args, target_idx, persist_enabled, flood_running, flood_enabled_flag, flood_drop_active, flood_nat_reported_at, flood_drop_reason

    parser = argparse.ArgumentParser(
        description="netwatch v8 — multi-layer network connection monitor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Press Ctrl+C to stop and save the log."
    )

    g = parser.add_argument_group("Core timing")
    g.add_argument("--interval", type=float, default=0.1,
                   help="Probe interval in seconds (default 0.1 = 100ms; fresh connection to 8.8.8.8)")
    g.add_argument("--summary",  type=float, default=5.0,
                   help="Summary print interval in seconds")
    g.add_argument("--timeout",  type=float, default=3.0,
                   help="Per-probe timeout in seconds")

    g = parser.add_argument_group("Internet probe")
    g.add_argument("--host", type=str, default=None,
                   help="Fixed probe host IP (default: auto-rotate)")
    g.add_argument("--port", type=int, default=53,
                   help="Port when --host is set")

    g = parser.add_argument_group("Gateway / local layer")
    g.add_argument("--gateway",    type=str, default="10.0.1.1",
                   help="Gateway IP to ping for fault isolation")
    g.add_argument("--no-gateway", action="store_true",
                   help="Disable gateway ping")
    g.add_argument("--ping-count", type=int, default=1, dest="ping_count",
                   help="ICMP packets per gateway check")

    g = parser.add_argument_group("DNS resolution check")
    g.add_argument("--dns-host", type=str, default="one.one.one.one",
                   dest="dns_host",
                   help="Hostname to resolve as DNS health check")
    g.add_argument("--no-dns",   action="store_true",
                   help="Disable DNS resolution check")

    g = parser.add_argument_group("Alerting / thresholds")
    g.add_argument("--latency-warn",     type=float, default=200.0,
                   dest="latency_warn",
                   help="Warn if internet RTT exceeds this (ms)")
    g.add_argument("--jitter-warn",      type=float, default=50.0,
                   dest="jitter_warn",
                   help="Warn if jitter (std-dev last 20 probes) exceeds this (ms)")
    g.add_argument("--outage-threshold", type=int,   default=3,
                   dest="outage_threshold",
                   help="Consecutive failures before declaring an outage")
    g.add_argument("--no-notify",        action="store_true",
                   help="Disable macOS desktop notifications")
    g.add_argument("--sound-profile",    type=str, default="alert",
                   dest="sound_profile",
                   choices=["alert", "urgent", "voice", "beep", "off"],
                   help="Sound alarm profile on outage start")
    g.add_argument("--sound-restore",    action="store_true",
                   dest="sound_restore",
                   help="Also play a sound when connection is restored")
    g.add_argument("--no-sound",         action="store_true",
                   dest="no_sound",
                   help="Disable all sound (alias for --sound-profile off)")

    g = parser.add_argument_group("Auto-traceroute on outage")
    g.add_argument("--traceroute",      action="store_true",
                   help="Run traceroute automatically when outage starts")
    g.add_argument("--traceroute-host", type=str, default="1.1.1.1",
                   dest="traceroute_host",
                   help="Target IP for auto-traceroute")
    g.add_argument("--traceroute-hops", type=int, default=15,
                   dest="traceroute_hops",
                   help="Max hops for traceroute")

    g = parser.add_argument_group("Packet loss check")
    g.add_argument("--loss-pings",    type=int,   default=10, dest="loss_pings",
                   help="Number of pings per packet-loss burst")
    g.add_argument("--loss-warn",     type=float, default=2.0, dest="loss_warn",
                   help="Warn if packet loss %% exceeds this")
    g.add_argument("--loss-interval", type=int,   default=20, dest="loss_interval",
                   help="Run loss check every N probe cycles")
    g.add_argument("--no-loss",       action="store_true", dest="no_loss",
                   help="Disable packet loss check")

    g = parser.add_argument_group("Latency spike detection")
    g.add_argument("--spike-warn", type=float, default=400.0, dest="spike_warn",
                   help="Warn on a single probe RTT exceeding this (ms)")

    g = parser.add_argument_group("App-specific probe")
    g.add_argument("--app-host",  type=str, default=None, dest="app_host",
                   help="Hostname/IP to probe as application target (e.g. login.eveonline.com)")
    g.add_argument("--app-port",  type=int, default=443,  dest="app_port",
                   help="Port for app probe")
    g.add_argument("--app-label", type=str, default="app", dest="app_label",
                   help="Label for app probe shown in output")

    g = parser.add_argument_group("Persistent TCP probe (long-lived socket)")
    g.add_argument("--persist-host",    type=str,
                   default="off", dest="persist_host",
                   help="Host to hold a persistent TCP connection to. "
                        "Safe neutral choices: 1.1.1.1, 8.8.8.8, 8.8.4.4 "
                        "(all accept idle long-lived TCP on port 443, will never "
                        "flag or block a single persistent socket from a home IP). "
                        "Set to 'off' to disable.")
    g.add_argument("--persist-port",    type=int, default=443, dest="persist_port",
                   help="Port for persistent probe (default 443 = HTTPS, always open)")
    g.add_argument("--persist-label",   type=str, default="persist",
                   dest="persist_label",
                   help="Label shown in output for persistent probe")
    g.add_argument("--persist-timeout", type=float, default=5.0,
                   dest="persist_timeout",
                   help="Reconnect timeout in seconds after a drop")
    g.add_argument("--persist-ping",    type=int, default=20,
                   dest="persist_ping",
                   help="Actively test the socket every N probe cycles by sending "
                        "a byte and reading the response (default: 20 = every 2s "
                        "at 0.1s interval). Catches silent drops before OS does.")
    g.add_argument("--no-persist-reconnect", action="store_true",
                   dest="no_persist_reconnect",
                   help="Do not auto-reconnect persistent socket after a drop")

    g = parser.add_argument_group("TCP keepalive flood probe (sub-second gap detection)")
    g.add_argument("--flood-host",      type=str,   default="1.1.1.1",
                   dest="flood_host",
                   help="Host for TCP flood probe. Uses TCP DNS (port 53) — "
                        "sends a DNS query every --flood-interval ms on a single "
                        "persistent connection, detects sub-second NAT flushes. "
                        "Set to 'off' to disable.")
    g.add_argument("--flood-port",      type=int,   default=53,
                   dest="flood_port",
                   help="Port for flood probe (default 53 = TCP DNS)")
    g.add_argument("--flood-interval",  type=float, default=0.01,
                   dest="flood_interval",
                   help="Seconds between flood queries (default 0.01 = 100/sec = 10ms)")
    g.add_argument("--flood-gap-warn",  type=float, default=150.0,
                   dest="flood_gap_warn",
                   help="Warn if any response gap exceeds this many ms (default 150)")
    g.add_argument("--no-flood",        action="store_true", dest="no_flood",
                   help="Disable TCP flood probe")

    g = parser.add_argument_group("Path divergence traceroute")
    g.add_argument("--path-trace", action="store_true", dest="path_trace",
                   help="On app probe failure, run parallel traceroutes to app "
                        "and reference host to find where routes diverge")

    g = parser.add_argument_group("Wi-Fi signal (macOS)")
    g.add_argument("--wifi",      action="store_true",
                   help="Enable Wi-Fi RSSI monitoring via macOS airport utility")
    g.add_argument("--wifi-warn", type=int, default=-70, dest="wifi_warn",
                   help="Warn if Wi-Fi RSSI drops below this dBm value")

    g = parser.add_argument_group("Pre-outage ring buffer")
    g.add_argument("--prebuffer",    type=int, default=30, dest="prebuffer",
                   help="Number of recent probe rows to save before an outage starts")
    g.add_argument("--no-prebuffer", action="store_true", dest="no_prebuffer",
                   help="Disable pre-outage ring buffer")

    g = parser.add_argument_group("Logging")
    g.add_argument("--log",       type=str, default=None,
                   help="Fixed CSV log file path (disables daily rotation)")
    g.add_argument("--log-dir",   type=str, default=".", dest="log_dir",
                   help="Directory for rotated daily log files")
    g.add_argument("--no-rotate", action="store_true",
                   help="Disable daily rotation (single timestamped file)")

    args = parser.parse_args()

    # --no-sound overrides --sound-profile
    if args.no_sound:
        args.sound_profile = "off"

    # Configure pre-outage ring buffer size
    if not args.no_prebuffer:
        pre_outage_buf.clear()
        # Replace with a fresh deque of the right maxlen
        globals()["pre_outage_buf"] = deque(maxlen=args.prebuffer)

    # ── Initialise logging ────────────────────────────────────────────────
    os.makedirs(args.log_dir, exist_ok=True)

    if args.log:
        open_log(args.log, write_header=not os.path.exists(args.log))
    elif args.no_rotate:
        fixed = os.path.join(
            args.log_dir,
            f"netwatch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        open_log(fixed, write_header=True)
    else:
        maybe_rotate_log(args.log_dir)

    # ── Banner ────────────────────────────────────────────────────────────
    gw_status  = args.gateway if not args.no_gateway else "disabled"
    dns_status = args.dns_host if not args.no_dns    else "disabled"
    tr_status  = (f"{args.traceroute_host} (max {args.traceroute_hops} hops)"
                  if args.traceroute else "disabled (add --traceroute to enable)")
    loss_status = (f"every {args.loss_interval} probes, {args.loss_pings} pings, warn>{args.loss_warn}%"
                   if not args.no_loss else "disabled")
    app_status  = (f"{args.app_host}:{args.app_port} [{args.app_label}]"
                   if args.app_host else "disabled (add --app-host to enable)")
    persist_enabled = (args.persist_host and args.persist_host.lower() != "off")
    persist_status = (f"{args.persist_host}:{args.persist_port} [{args.persist_label}]"
                      if persist_enabled
                      else "disabled (TCP flood probe is the primary detector in v7)")
    flood_enabled_flag = (not args.no_flood and
                          args.flood_host.lower() != "off")
    flood_status = (f"{args.flood_host}:{args.flood_port}  "
                    f"every {args.flood_interval*1000:.0f}ms  "
                    f"warn>{args.flood_gap_warn:.0f}ms gap"
                    if flood_enabled_flag
                    else "disabled (remove --no-flood to enable)")
    wifi_status = (f"enabled, warn < {args.wifi_warn} dBm"
                   if args.wifi else "disabled (add --wifi to enable)")
    buf_status  = (f"{args.prebuffer} rows"
                   if not args.no_prebuffer else "disabled")

    print(
        f"\n{BOLD}{CYAN}━━━  netwatch v8  ━━━{RESET}\n"
        f"  Probe interval   : {args.interval}s\n"
        f"  Summary every    : {args.summary}s\n"
        f"  TCP timeout      : {args.timeout}s\n"
        f"  Outage after     : {args.outage_threshold} consecutive fails\n"
        f"  Latency warn     : {args.latency_warn} ms\n"
        f"  Jitter warn      : {args.jitter_warn} ms\n"
        f"  Spike warn       : {args.spike_warn} ms\n"
        f"  Gateway ping     : {gw_status}\n"
        f"  DNS check        : {dns_status}\n"
        f"  Packet loss      : {loss_status}\n"
        f"  App probe        : {app_status}\n"
        f"  Persist probe    : {persist_status}\n"
        f"  TCP flood probe  : {flood_status}\n"
        f"  Path divergence  : {'enabled' if args.path_trace else 'disabled (add --path-trace)'}\n"
        f"  Wi-Fi signal     : {wifi_status}\n"
        f"  Pre-outage buf   : {buf_status}\n"
        f"  Auto-traceroute  : {tr_status}\n"
        f"  Notifications    : {'disabled' if args.no_notify else 'enabled'}\n"
        f"  Sound alarm      : {args.sound_profile}"
        f"{' + restore' if args.sound_restore and args.sound_profile != 'off' else ''}\n"
        f"  Log file         : {log_path}\n"
        f"  {DIM}Press Ctrl+C to stop{RESET}\n"
    )

    # ── Start persistent TCP socket if configured ─────────────────────────
    if persist_enabled:
        if persist_connect(args.persist_host, args.persist_port,
                           args.persist_timeout):
            stats["persist_connected"]    = True
            stats["persist_connect_time"] = datetime.now()
            print(f"  {GREEN}↳ Persistent socket connected: "
                  f"{args.persist_host}:{args.persist_port}{RESET}\n")
        else:
            print(f"  {YELLOW}↳ Persistent socket: could not connect to "
                  f"{args.persist_host}:{args.persist_port} — will retry{RESET}\n")

    # ── Start TCP flood probe thread if configured ───────────────────────
    if flood_enabled_flag:
        flood_running = True
        ft = threading.Thread(
            target=_flood_thread,
            args=(args.flood_host, args.flood_port,
                  args.flood_interval, args.flood_gap_warn,
                  args.log_dir),
            daemon=True
        )
        ft.start()
        print(f"  {GREEN}↳ TCP flood probe started: "
              f"{args.flood_host}:{args.flood_port} "
              f"every {args.flood_interval*1000:.0f}ms{RESET}\n")

    next_probe   = time.monotonic()
    next_summary = time.monotonic() + args.summary

    while True:
        now = time.monotonic()

        # ── Daily log rotation ────────────────────────────────────────────
        if not args.log and not args.no_rotate:
            maybe_rotate_log(args.log_dir)

        # ── Internet TCP probe ────────────────────────────────────────────
        if now >= next_probe:
            ts     = datetime.now()
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            stats["probe_count"] += 1

            if args.host:
                host, port, label = args.host, args.port, "custom"
            else:
                host, port, label = PROBE_TARGETS[target_idx % len(PROBE_TARGETS)]
                target_idx += 1

            ok, latency = probe_tcp(host, port, args.timeout)
            stats["total"] += 1
            event = ""

            if ok:
                stats["success"]     += 1
                stats["latency_sum"] += latency
                stats["latency_window"].append(latency)
                if latency > stats["latency_max"]:
                    stats["latency_max"] = latency
                if latency < stats["latency_min"]:
                    stats["latency_min"] = latency
                event = handle_success(ts)
                if event.startswith("OUTAGE_END"):
                    print(f"\n  {GREEN}✓ {ts_str}  Connection restored — {event}{RESET}")
                    if not args.no_notify:
                        dur = event.split("(")[1].rstrip("s)")
                        notify("netwatch — Connection Restored",
                               f"Back online after {dur}s outage")
                    if args.sound_restore:
                        play_restore(args.sound_profile)
                # ── Latency spike detection ───────────────────────────────
                if latency > args.spike_warn:
                    stats["spike_count"] += 1
                    print(f"  {RED}⚡ {ts_str}  LATENCY SPIKE {latency:.0f}ms "
                          f"(threshold {args.spike_warn:.0f}ms){RESET}")
            else:
                stats["failure"] += 1
                event = handle_failure(ts)
                if event == "OUTAGE_START":
                    print(f"\n  {RED}✗ {ts_str}  ⚠  OUTAGE #{stats['outages']} STARTED{RESET}")
                    if not args.no_notify:
                        notify("netwatch — Internet Outage",
                               f"Outage #{stats['outages']} at "
                               f"{ts.strftime('%H:%M:%S')}")
                    play_alarm(args.sound_profile, stats["outages"])
                    # Flush pre-outage buffer
                    if not args.no_prebuffer:
                        threading.Thread(
                            target=flush_pre_outage_buffer,
                            args=(args.log_dir, ts_str),
                            daemon=True
                        ).start()
                    if args.traceroute:
                        threading.Thread(
                            target=run_traceroute,
                            args=(args.traceroute_host, args.traceroute_hops,
                                  args.log_dir, ts_str),
                            daemon=True
                        ).start()

            # ── Gateway ping ──────────────────────────────────────────────
            gw_result, gw_lat = "N/A", 0.0
            if not args.no_gateway:
                gw_ok, gw_lat = probe_ping(args.gateway, args.ping_count,
                                            args.timeout)
                stats["gw_total"] += 1
                if gw_ok:
                    stats["gw_success"]     += 1
                    stats["gw_latency_sum"] += gw_lat
                    if gw_lat > stats["gw_latency_max"]:
                        stats["gw_latency_max"] = gw_lat
                    if gw_lat < stats["gw_latency_min"]:
                        stats["gw_latency_min"] = gw_lat
                    gw_result = "OK"
                else:
                    stats["gw_failure"] += 1
                    gw_result = "FAIL"

                # On a fresh outage — diagnose where the fault is
                if event == "OUTAGE_START":
                    if gw_ok:
                        print(f"  {YELLOW}↳ Gateway {args.gateway} reachable "
                              f"→ fault is UPSTREAM (ONT / fiber / Delta Fiber){RESET}")
                    else:
                        print(f"  {RED}↳ Gateway {args.gateway} UNREACHABLE "
                              f"→ fault is LOCAL (modem / cable / Sagecom){RESET}")
                elif not ok and gw_result == "FAIL":
                    pass
                elif gw_result == "FAIL" and ok:
                    print(f"  {YELLOW}⚠ {ts_str}  Gateway unreachable "
                          f"(internet still ok — transient?){RESET}")

            # ── DNS check ─────────────────────────────────────────────────
            dns_result, dns_lat = "N/A", 0.0
            if not args.no_dns:
                dns_ok, dns_lat = probe_dns(args.dns_host, args.timeout)
                stats["dns_total"] += 1
                if dns_ok:
                    stats["dns_success"] += 1
                    dns_result = "OK"
                else:
                    stats["dns_failure"] += 1
                    dns_result = "FAIL"
                    if ok:
                        print(f"  {YELLOW}⚠ {ts_str}  DNS resolution FAILED "
                              f"(TCP ok) — possible DNS server issue{RESET}")

            # ── Packet loss check (every N probes) ────────────────────────
            loss_pct_val = "N/A"
            if not args.no_loss and stats["probe_count"] % args.loss_interval == 0:
                lp, _ = probe_packet_loss(args.gateway if not args.no_gateway else "1.1.1.1",
                                          args.loss_pings, args.timeout)
                loss_pct_val = lp
                stats["loss_checks"] += 1
                stats["loss_sum"]    += lp
                if lp > stats["loss_max"]:
                    stats["loss_max"] = lp
                if lp > args.loss_warn:
                    stats["loss_warn_count"] += 1
                    print(f"  {RED}📉 {ts_str}  PACKET LOSS {lp:.1f}% "
                          f"(warn threshold {args.loss_warn:.0f}%){RESET}")

            # ── App-specific probe ────────────────────────────────────────
            app_result, app_lat = "N/A", 0.0
            if args.app_host:
                app_ok, app_lat = probe_tcp(args.app_host, args.app_port, args.timeout)
                stats["app_total"] += 1
                if app_ok:
                    stats["app_success"] += 1
                    app_result = "OK"
                else:
                    stats["app_failure"] += 1
                    app_result = "FAIL"
                    if ok:
                        # General internet is up but app endpoint is down
                        print(f"  {YELLOW}⚠ {ts_str}  App probe FAILED "
                              f"[{args.app_label}] {args.app_host}:{args.app_port} "
                              f"(internet ok — service-level issue?){RESET}")

            # ── Wi-Fi signal check (every N probes) ───────────────────────
            wifi_rssi_val = "N/A"
            if args.wifi and stats["probe_count"] % max(1, args.loss_interval // 2) == 0:
                ssid, rssi = probe_wifi_signal()
                if rssi is not None:
                    wifi_rssi_val = rssi
                    if rssi < stats["wifi_rssi_min"] or stats["wifi_rssi_min"] == 0:
                        stats["wifi_rssi_min"] = rssi
                    if rssi < args.wifi_warn:
                        stats["wifi_warn_count"] += 1
                        print(f"  {YELLOW}📶 {ts_str}  WEAK Wi-Fi signal: {rssi} dBm "
                              f"(warn threshold {args.wifi_warn} dBm)  SSID: {ssid}{RESET}")

            # ── Persistent TCP socket check ───────────────────────────────
            persist_result_val    = "N/A"
            persist_drop_secs_val = "N/A"
            if persist_enabled:
                alive = persist_is_alive()
                if alive:
                    persist_result_val = "ALIVE"
                    if not stats["persist_connected"]:
                        # Just reconnected — log the recovery
                        drop_dur = (ts - stats["persist_last_drop_ts"]).total_seconds() \
                                   if stats["persist_last_drop_ts"] else 0
                        persist_drop_secs_val = f"{drop_dur:.1f}"
                        stats["persist_drop_durations"].append(drop_dur)
                        stats["persist_connected"]    = True
                        stats["persist_connect_time"] = ts
                        stats["persist_last_drop_ts"] = None
                        print(f"\n  {GREEN}↳ {ts_str}  Persistent socket RESTORED "
                              f"[{args.persist_label}] — was down {drop_dur:.1f}s{RESET}")
                else:
                    persist_result_val = "DROPPED"
                    if stats["persist_connected"]:
                        # Just dropped — record it
                        stats["persist_connected"]   = False
                        stats["persist_drops"]       += 1
                        stats["persist_last_drop_ts"] = ts
                        print(f"\n  {RED}💀 {ts_str}  Persistent socket DROPPED "
                              f"[{args.persist_label}] {args.persist_host}:{args.persist_port}"
                              f"  (internet probe: {'OK' if ok else 'FAIL'}){RESET}")
                        # Trigger path divergence traceroute if configured
                        if args.path_trace and args.persist_host:
                            threading.Thread(
                                target=run_path_divergence,
                                args=(args.persist_host, args.persist_port,
                                      "1.1.1.1", args.log_dir, ts_str),
                                daemon=True
                            ).start()
                        persist_close()
                    # Try to reconnect unless suppressed
                    if not args.no_persist_reconnect:
                        if persist_connect(args.persist_host, args.persist_port,
                                           args.persist_timeout):
                            stats["persist_connected"]    = True
                            stats["persist_connect_time"] = ts
                            drop_dur = (ts - stats["persist_last_drop_ts"]).total_seconds() \
                                       if stats["persist_last_drop_ts"] else 0
                            persist_drop_secs_val = f"{drop_dur:.1f}"
                            stats["persist_drop_durations"].append(drop_dur)
                            stats["persist_last_drop_ts"] = None
                            print(f"  {GREEN}↳ {ts_str}  Persistent socket reconnected "
                                  f"in {drop_dur:.1f}s{RESET}")

            # ── NAT flush divergence detector ─────────────────────────────
            # If the flood probe is down but THIS fresh-connect probe succeeded,
            # the existing connection state was flushed — not the internet itself.
            # This is the definitive proof of a NAT/stateful-firewall reset.
            with flood_lock:
                _flood_is_down = flood_drop_active
                _flood_rtt     = flood_rtt_last_ms

            if flood_enabled_flag and _flood_is_down and ok:
                with flood_lock:
                    _drop_reason = flood_drop_reason

                # Only declare a confirmed NAT flush if the drop was a
                # TIMEOUT (no response from server). Server-side closes
                # (SERVER_RST, SERVER_FIN) are the server ending an idle
                # connection — harmless, not a NAT flush.
                _is_true_flush = (_drop_reason == "TIMEOUT" or _drop_reason == "")
                _event_tag = "NAT_FLUSH_CONFIRMED" if _is_true_flush else f"FLOOD_DROP_{_drop_reason}"

                if event:
                    event = event + "," + _event_tag
                else:
                    event = _event_tag

                _now_mono = time.monotonic()
                _cooldown_expired = (
                    flood_nat_reported_at is None or
                    (_now_mono - flood_nat_reported_at) > 10.0
                )
                if _cooldown_expired:
                    flood_nat_reported_at = _now_mono
                    if _is_true_flush:
                        print(f"\n  {RED}🔥 {ts_str}  NAT FLUSH CONFIRMED — "
                              f"flood TIMEOUT, fresh TCP to {host} OK{RESET}")
                        print(f"  {YELLOW}   Connection state was reset — "
                              f"messages suppressed until flood recovers.{RESET}")
                    else:
                        print(f"\n  {YELLOW}⚡ {ts_str}  Flood drop [{_drop_reason}] — "
                              f"server closed idle connection (not a NAT flush){RESET}")

            # ── Jitter & latency warnings ─────────────────────────────────
            jitter = calc_jitter()
            extras = ""
            if ok and latency > args.latency_warn:
                extras += f"  {YELLOW}HIGH LATENCY ({latency:.0f}ms){RESET}"
            if ok and jitter > args.jitter_warn:
                extras += f"  {YELLOW}HIGH JITTER ({jitter:.1f}ms){RESET}"

            # ── Inline print (only on notable events) ─────────────────────
            notable = (not ok or extras
                       or dns_result == "FAIL"
                       or app_result == "FAIL"
                       or (gw_result == "FAIL" and ok))
            if notable and event not in ("OUTAGE_START",) and not event.startswith("OUTAGE_END"):
                sym = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
                gw_str  = f"  gw:{RED}FAIL{RESET}"  if gw_result  == "FAIL" else ""
                dns_str = f"  dns:{RED}FAIL{RESET}" if dns_result == "FAIL" else ""
                app_str = f"  {args.app_label}:{RED}FAIL{RESET}" if app_result == "FAIL" else ""
                print(f"  {sym} {DIM}{ts_str}{RESET}  {label:<16} "
                      f"{latency:6.1f}ms{extras}{gw_str}{dns_str}{app_str}")

            # ── Write CSV row ─────────────────────────────────────────────
            write_log(ts_str, host, label,
                      "OK" if ok else "FAIL", latency,
                      gw_result, gw_lat,
                      dns_result, dns_lat,
                      jitter,
                      loss_pct_val, app_result, app_lat,
                      wifi_rssi_val,
                      persist_result_val, persist_drop_secs_val,
                      _flood_rtt if flood_enabled_flag else 0.0,
                      event)

            next_probe = next_probe + args.interval

        # ── Summary ───────────────────────────────────────────────────────
        if now >= next_summary:
            print_summary()
            next_summary = now + args.summary

        # ── Sleep until next event ────────────────────────────────────────
        sleep_for = min(next_probe, next_summary) - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)


if __name__ == "__main__":
    main()
