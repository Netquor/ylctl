# Live capture and logs

Two ways to watch what a Yealink phone is doing while you test. Both were tested on a T41S running 66.85 (phone B).

## capture: stream the phone's packet trace

- Start: `POST servlet?m=mod_configfile&q=downloadcapture&type=start&pcaptype=1` (multipart form, no fields). The answer is a never-ending chunked download of a classic pcap file. VERIFIED: packets arrive as they happen, not at the end.
- Stop: the same URL with `type=stop` and the CSRF token. Status: `q=getcapturestatus` returns true or false. VERIFIED.
- Closing the connection also stops the capture within about 5 seconds (seen by the first worker). ylctl still sends the stop call and checks the status afterwards.
- The trace covers the phone's whole network port, so on a busy VLAN most lines are other devices (mDNS and the like). Use `--ip`, `--port` or `--filter`.
- SIP over TLS (5061) is encrypted: you see TLS records and sizes, not messages. Use `logs follow` for readable SIP.

```sh
ylctl capture follow PHONE                       # one line per packet, Ctrl-C stops
ylctl capture follow PHONE --filter tls --ip PBX_IP
ylctl capture follow PHONE --json                # one JSON object per line (for scripts and AI)
ylctl capture follow PHONE --format pcap | wireshark -k -i -
ylctl capture follow PHONE --out trace.pcap --duration 60s
ylctl capture status PHONE ; ylctl capture stop PHONE
```

Safety limits: 5 minutes and 20 MiB by default, a stop is always attempted on exit, and a running capture is never taken over without `--force`.

## logs: the phone's syslog, live

`logs follow` sets the phone's remote syslog (Settings > Configuration) to this computer, receives UDP syslog from that phone only, and puts the old values back on exit. Only these fields are ever written: SyslogSwitch, SyslogServerName, SyslogServerPort, SyslogTransportType, SyslogLevel (facility and prepend-MAC are allowed by the client but not changed by follow).

- The original values are saved to `syslog-restore-<phone>.json` (mode 0600) in the ylctl config folder before the change. If a run is killed, `ylctl logs restore PHONE` puts them back. A later `follow` keeps those original values rather than saving the temporary ones.
- VERIFIED on phone B: 270 lines arrived in 25 seconds while `provision-now` ran, and the phone read back syslog off, level 3 afterwards.
- Level 6 is the useful one. Console output shows the phone's own configuration and SIP activity in readable text even over TLS.

```sh
ylctl logs show PHONE                  # read-only
ylctl logs follow PHONE --dry-run      # show the change, send nothing
ylctl logs follow PHONE --grep 'REGISTER|INVITE' --duration 2m
ylctl logs follow PHONE --json
ylctl logs restore PHONE
```

## Not yet verified

- Firmware 66.86 (phone A) for the syslog write; the capture endpoints are the same page script on both.
- Killing the process with SIGKILL mid-run then `logs restore` (designed for, not yet exercised).
- TCP or TLS syslog transport (the receiver is UDP only).

## Keys while following

On a terminal, `logs follow` and `capture follow` show a key bar pinned to the bottom row while output scrolls above it:
`q` quit (restores the phone first), `s` start or stop saving to a file in the current folder (`ylctl-logs-HOST-TIME.log`, or a valid `.pcap` for capture, from that moment on), `c` clear, `?` redraw the bar. Ctrl-C works as `q`. Lines are colored by module (the phone's `SYS`, `SIP`, `UIMG` and so on) or by syslog tag; errors stay red and `SIP` is always bright green. Colors and keys are off when output is piped. VERIFIED through a pseudo-terminal on phone A (66.86): bar, save toggle (102 records), quit and restore.
