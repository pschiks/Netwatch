# netwatch

A multi-layer network connection monitor for diagnosing intermittent internet
problems — particularly the kind that crash online games and drop streaming
audio while a standard ping test shows nothing wrong.

Originally written to investigate recurring connection drops on a Delta Fiber
(Netherlands) residential connection that crashed Eve Online and audio streaming
but left the router and a standard connectivity check completely unaffected.
The monitor proved the cause: periodic NAT state table flushes on upstream
network equipment.

Special thanks to Claude.ai

---

## Requirements

- **Python 3.10+** (uses `match`-free code, works on 3.8+ actually)
- **macOS** — notifications, sound alarms, and Wi-Fi RSSI use macOS-only tools
  (`osascript`, `afplay`, `say`, `airport`). All other features work on Linux.
- No external Python packages required — stdlib only.

---

## Quick start

```bash
# Minimal — just run it
python3 netwatch9.py

# Recommended for ISP fault investigation
python3 netwatch9.py --path-trace --traceroute --sound-profile urgent

# Full setup for gaming/streaming diagnosis
python3 netwatch9.py \
  --app-host login.eveonline.com --app-label "Eve" \
  --wifi --wifi-warn -70 \
  --path-trace --traceroute \
  --sound-profile urgent
```

Press **Ctrl+C** to stop and save the log.

---

## How it works

The monitor runs **two parallel detection strategies** at all times:

### 1. Fresh-connect probe (main loop)

Every **100ms**, opens a brand-new TCP connection to a rotating list of public
DNS servers (Google, Cloudflare, OpenDNS) on port 53. If the connection
succeeds, internet routing is alive. If it fails, it's an outage.

**What this catches:** Full internet outages, routing failures, DNS problems.

**What this misses:** Events that only kill *existing* connections — because it
always opens a new connection that gets a fresh NAT table entry.

### 2. TCP flood probe (background thread)

Maintains a **single persistent TCP connection** to `1.1.1.1:53` and sends a
DNS query every **10ms** on that same connection — 100 times per second. Any
gap in responses is flagged immediately with millisecond precision.

**What this catches:** Sub-second NAT state table flushes, brief routing
blackouts, anything that kills a long-lived connection. This is what Eve Online,
PS5 games, and streaming audio use — they hold one connection open for hours.

**Why this matters:** When a NAT flush happens, existing connections die
instantly while new ones work fine. A standard connectivity check (which opens
a new connection every time) will show nothing wrong — only a persistent
connection probe detects the event.

### NAT flush confirmation

When the flood probe drops with a **TIMEOUT** (no response — the connection was
silently killed) at the same moment that a fresh TCP connection to a *different*
server succeeds, the monitor logs:

```
🔥 NAT FLUSH CONFIRMED — flood TIMEOUT, fresh TCP to 8.8.8.8 OK
```

This is definitive proof that existing connection state was reset on upstream
network equipment, not that the internet went down. This is the key evidence
for an ISP support ticket.

### Drop reason classification

Not every flood probe drop is a NAT flush. The monitor classifies each drop:

| Reason | Meaning | Alarm? |
|---|---|---|
| `TIMEOUT` | No response — true NAT flush or route drop | Yes — `🔥` |
| `SERVER_RST` | Server sent TCP RST — idle connection closed by server | No — `⚡` yellow |
| `SERVER_FIN` | Server closed cleanly — idle timeout | No — `⚡` yellow |
| `BROKEN_PIPE` | Write failed — server gone | No |

`SERVER_RST` and `SERVER_FIN` are completely normal — Cloudflare's DNS servers
close idle TCP connections after a short timeout. These are harmless and do not
correlate with application disconnects.

---

## Probe targets

The fresh-connect probe rotates through these targets. Quad9 (`9.9.9.9`) was
deliberately excluded — its security filtering causes high latency variance and
frequent timeouts that generate false alarms.

| IP | Label | Notes |
|---|---|---|
| `8.8.8.8` | Google DNS | AMS-IX peering, very stable |
| `1.1.1.1` | Cloudflare DNS | AMS-IX peering, also flood probe target |
| `208.67.222.222` | OpenDNS | Cisco, good EU presence |
| `1.0.0.1` | Cloudflare alt | Different anycast node than `1.1.1.1` |
| `8.8.4.4` | Google alt | Different anycast node than `8.8.8.8` |

---

## Output

### Live terminal

Every 5 seconds a summary is printed:

```
────────────────────────────────────────────────────────────────────────────
  [18:12:50]  session uptime 01:58:36
  Internet: probes  71142  OK 71142  FAIL    0  avail 100.0%
  Latency : avg    8.5 ms  min    3.9 ms  max   69.6 ms  jitter   2.0 ms
  Gateway : 10.0.1.1         checks 71142  OK 100.0%  avg    1.4 ms
  DNS     : one.one.one.one  checks 71142  OK 100.0%
  PktLoss : checks 3557  avg   0.0%  max 0.0%  warn events 0
  TCPFlood: 1.1.1.1:53  state UP  gaps 0  last drop: SERVER_RST
  Outages :   0  total down 0.0s  log → ./netwatch_20260322.csv
```

Notable events are printed inline as they happen:

```
⚡ 18:12:49.863  LATENCY SPIKE 1008ms (threshold 400ms)
🔥 18:12:50.100  NAT FLUSH CONFIRMED — flood TIMEOUT, fresh TCP to 8.8.8.8 OK
⚡ 18:12:50.450  TCP-flood RESTORED — gap 350ms  reason was: TIMEOUT
```

### CSV log files

One CSV file per day in the log directory (`./netwatch_YYYYMMDD.csv`).
Columns:

| Column | Description |
|---|---|
| `timestamp` | Probe timestamp with millisecond precision |
| `probe_host` | Target IP of this probe |
| `probe_label` | Human label (e.g. "Google DNS") |
| `result` | `OK` or `FAIL` |
| `latency_ms` | Round-trip time in ms |
| `gateway_result` | `OK`, `FAIL`, or `N/A` |
| `gateway_latency_ms` | Gateway ping RTT |
| `dns_result` | `OK`, `FAIL`, or `N/A` |
| `dns_latency_ms` | DNS resolution time |
| `jitter_ms` | Outlier-filtered standard deviation of last 20 samples |
| `loss_pct` | Packet loss % from burst ping, or `N/A` |
| `app_result` | App probe result, or `N/A` |
| `app_latency_ms` | App probe RTT |
| `wifi_rssi` | Wi-Fi signal in dBm, or `N/A` |
| `persist_result` | Persistent probe state, or `N/A` |
| `persist_drop_secs` | Recovery time after persist drop |
| `flood_rtt_ms` | Last flood probe RTT (for post-mortem timeline) |
| `event` | Event tags: `OUTAGE_START`, `OUTAGE_END`, `NAT_FLUSH_CONFIRMED`, `FLOOD_DROP_SERVER_RST`, etc. |

### Additional output files

| File | When created | Contents |
|---|---|---|
| `traceroute_TIMESTAMP.txt` | On outage start (with `--traceroute`) | Full traceroute to reference host |
| `path_divergence_TIMESTAMP.txt` | On flood TIMEOUT (with `--path-trace`) | Side-by-side traceroutes to flood host and `1.1.1.1`, showing divergence hop |
| `premonition_TIMESTAMP.csv` | On outage start | Last N probe rows before the outage (pre-outage ring buffer) |

---

## All options

### Core timing

| Option | Default | Description |
|---|---|---|
| `--interval SECS` | `0.1` | Fresh-connect probe interval (100ms) |
| `--summary SECS` | `5.0` | Summary print interval |
| `--timeout SECS` | `3.0` | Per-probe TCP timeout |

### Internet probe

| Option | Default | Description |
|---|---|---|
| `--host HOST` | auto-rotate | Fix probe to a single host instead of rotating |
| `--port PORT` | `53` | Port when `--host` is set |

### Gateway / local layer

| Option | Default | Description |
|---|---|---|
| `--gateway IP` | `10.0.1.1` | Gateway IP for ICMP ping |
| `--no-gateway` | — | Disable gateway ping |
| `--ping-count N` | `1` | ICMP packets per gateway check |

### DNS resolution check

| Option | Default | Description |
|---|---|---|
| `--dns-host HOSTNAME` | `one.one.one.one` | Hostname to resolve as DNS health check |
| `--no-dns` | — | Disable DNS resolution check |

### Alerting / thresholds

| Option | Default | Description |
|---|---|---|
| `--latency-warn MS` | `200` | Warn if RTT exceeds this |
| `--jitter-warn MS` | `50` | Warn if outlier-filtered jitter exceeds this |
| `--spike-warn MS` | `400` | Warn on a single probe exceeding this |
| `--outage-threshold N` | `3` | Consecutive failures before declaring an outage |
| `--no-notify` | — | Disable macOS desktop notifications |
| `--sound-profile NAME` | `alert` | Alarm on outage: `alert` `urgent` `voice` `beep` `off` |
| `--sound-restore` | — | Also play sound on connection restore |
| `--no-sound` | — | Silence all sounds |

### Auto-traceroute on outage

| Option | Default | Description |
|---|---|---|
| `--traceroute` | — | Run traceroute automatically when outage starts |
| `--traceroute-host IP` | `1.1.1.1` | Target for auto-traceroute |
| `--traceroute-hops N` | `15` | Max hops |

### Packet loss check

| Option | Default | Description |
|---|---|---|
| `--loss-pings N` | `10` | Pings per burst |
| `--loss-warn PCT` | `2.0` | Warn if loss exceeds this % |
| `--loss-interval N` | `20` | Run loss check every N probe cycles |
| `--no-loss` | — | Disable packet loss check |

### App-specific probe

Probe a specific application endpoint (e.g. a game login server) independently
from the general internet check. If the app probe fails while general internet
is fine, it's a service-level issue rather than an ISP problem.

| Option | Default | Description |
|---|---|---|
| `--app-host HOST` | — | Hostname/IP to probe (e.g. `login.eveonline.com`) |
| `--app-port PORT` | `443` | Port for app probe |
| `--app-label LABEL` | `app` | Label shown in output |

### Persistent TCP probe

Holds a long-lived TCP connection open (like a game client does) and checks its
liveness. Mostly superseded by the TCP flood probe but available for additional
parallel testing.

| Option | Default | Description |
|---|---|---|
| `--persist-host HOST` | `off` | Host to hold persistent connection to (`off` = disabled) |
| `--persist-port PORT` | `443` | Port |
| `--persist-label LABEL` | `persist` | Label shown in output |
| `--persist-timeout SECS` | `5.0` | Reconnect timeout |
| `--no-persist-reconnect` | — | Don't auto-reconnect after drop |

### TCP keepalive flood probe

The primary NAT flush detector. Sends DNS queries every 10ms on a single
persistent connection and measures response gaps with millisecond precision.

| Option | Default | Description |
|---|---|---|
| `--flood-host HOST` | `1.1.1.1` | Target for flood probe (`off` = disabled) |
| `--flood-port PORT` | `53` | Port (TCP DNS) |
| `--flood-interval SECS` | `0.01` | Interval between queries (10ms) |
| `--flood-gap-warn MS` | `150` | Warn on response gap exceeding this |
| `--no-flood` | — | Disable flood probe |

### Path divergence traceroute

When the flood probe drops with a TIMEOUT, runs traceroutes to both the flood
host and `1.1.1.1` in parallel and saves a diff showing where the routes
diverge. This identifies the specific router hop responsible.

| Option | Default | Description |
|---|---|---|
| `--path-trace` | — | Enable path divergence on flood TIMEOUT |

### Wi-Fi signal (macOS)

| Option | Default | Description |
|---|---|---|
| `--wifi` | — | Enable RSSI monitoring via macOS `airport` utility |
| `--wifi-warn DBM` | `-70` | Warn if signal drops below this |

### Pre-outage ring buffer

Keeps the last N probe rows in memory. When an outage starts, flushes them to
`premonition_TIMESTAMP.csv` so you can see what was happening in the seconds
before the crash.

| Option | Default | Description |
|---|---|---|
| `--prebuffer N` | `30` | Rows to keep before outage |
| `--no-prebuffer` | — | Disable |

### Logging

| Option | Default | Description |
|---|---|---|
| `--log FILE` | — | Fixed log file path (disables daily rotation) |
| `--log-dir DIR` | `.` | Directory for daily rotated log files |
| `--no-rotate` | — | Use a single timestamped file instead of daily rotation |

---

## Jitter calculation — outlier filtering

Jitter is reported as the standard deviation of the last 20 latency samples.
Without filtering, a single slow probe (e.g. 1000ms while everything else is
8ms) inflates the standard deviation to ~217ms, causing "HIGH JITTER" warnings
on every subsequent probe for ~2 seconds as the outlier slides out of the
window. This is noise, not signal.

**The fix:** any sample more than **10× the window mean** is excluded from the
standard deviation calculation. The spike is already reported separately by the
latency spike detector, so it is not silently dropped — it just does not
distort the jitter metric for subsequent probes.

If all samples in the window are outliers (genuine network degradation), the
full window is used as a fallback so real sustained jitter is never hidden.

---

## Analysing logs — netwatch_analyse.py

A companion analysis script processes log files and produces a plain-text
report. It streams files line by line and is safe for 1 GB+ log files.

```bash
python3 netwatch_analyse.py
python3 netwatch_analyse.py --since 2026-03-21
python3 netwatch_analyse.py --folder ~/netlogs --output report.txt
```

The report includes:

1. **Overview table** — counts of every event type with severity
2. **Outages** — start/end/duration, with gateway status to identify whether
   fault is local or upstream
3. **TCP flood gaps** — sub-second drops with ms timestamps
4. **NAT flush events** — TIMEOUT drops only (true NAT flush proof)
5. **Server-side closes** — SERVER_RST/SERVER_FIN events listed separately
   as harmless
6. **Drop reason breakdown** — count of each reason type
7. **Flood RTT statistics** — average/min/max and spike correlation
8. **Packet loss events**
9. **Latency spikes**
10. **Jitter bursts**
11. **DNS / gateway failures**
12. **Delta Fiber summary** — plain-language description ready to paste into
    an ISP support ticket

---

## Understanding the events

### The hiccup that started this project

All devices on the network (wired and wireless) lose their existing connections
simultaneously at around the same time each day. A standard connectivity check
shows nothing wrong. The router does not reboot. The WAN IP does not change.

**Why standard tools miss it:** A ping test or `curl` check opens a new
connection each time. When a NAT state table is flushed, new connections get
fresh table entries and succeed immediately. Only connections that were already
established (games, streaming, VoIP) are killed.

**How netwatch catches it:** The TCP flood probe holds one connection open
continuously. A NAT flush kills it within milliseconds.

### Reading the evidence

```
⚡ 15:30:28.237  TCP-flood DROP [TIMEOUT] on 1.1.1.1:53
```
The persistent connection died with no response — not a graceful server close.
Combined with all fresh-connect probes succeeding, this is a NAT flush.

```
⚡ 15:30:28.237  TCP-flood DROP [SERVER_RST] on 1.1.1.1:53
⚡ 15:30:28.237  Flood drop [SERVER_RST] — server closed idle connection (not a NAT flush)
```
Cloudflare closed an idle connection from their end. Completely normal.
No action required.

### Duration matters

A TIMEOUT that lasts **< 100ms** will usually not crash applications — TCP
retransmit timers can cover the gap. A TIMEOUT lasting **300ms+** will kill
most game sessions and drop streaming audio. The flood probe's recovery message
shows the exact gap duration:

```
⚡ 15:30:35.100  TCP-flood RESTORED — gap 6863ms  reason was: TIMEOUT
```

A 6.8-second gap will crash everything. A 30ms gap may go unnoticed by apps.

---

## Files produced

Running `python3 netwatch9.py --path-trace --traceroute` in a directory
will produce:

```
./netwatch_20260322.csv          ← daily probe log (rename suffix changes daily)
./traceroute_15-30-28.txt        ← auto-traceroute triggered at 15:30:28
./path_divergence_15-30-28.txt   ← route diff saved at flood drop
./premonition_15-30-28.csv       ← 30 rows before the outage
./netwatch_report_TIMESTAMP.txt  ← analysis report (from netwatch_analyse.py)
```

---

## Known limitations

- **macOS only** for sound alarms, desktop notifications, and Wi-Fi RSSI.
  All network probing features work on Linux.
- The TCP flood probe creates ~5 KB/min of DNS traffic to `1.1.1.1`. This is
  negligible but is real traffic.
- At `--interval 0.01` (10ms) the fresh-connect probe opens 100 TCP connections
  per second. This is the default `--interval 0.1` (100ms = 10/sec) which is
  safe. Reducing interval below 0.05 is not recommended.
- Log files grow at approximately 2–5 MB per hour at default settings.
  Use `--log-dir` to point them at a drive with sufficient space.
