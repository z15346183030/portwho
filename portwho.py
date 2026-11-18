#!/usr/bin/env python3
"""portwho — who has that port?

Given a port number, finds every network connection on that port and
identifies the process behind it: name, PID, path, start time.

Usage:
    portwho 3000            # who is listening on port 3000?
    portwho 3000 --all      # include established, time_wait, etc.
    portwho 3000 --json     # machine-readable
    portwho 3000 --explain  # show how each field was obtained
    portwho --tcp 3000      # TCP only (default)
    portwho --udp 3000      # UDP only

Exit codes:
    0 — found at least one match
    1 — port found but no process identified (permission denied)
    2 — no connection on that port, or bad input
"""

import argparse
import csv
import io
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Connection model
# ---------------------------------------------------------------------------

class Connection:
    """One row from the system's network table."""

    __slots__ = (
        "proto", "local_addr", "local_port", "remote_addr",
        "remote_port", "state", "pid",
    )

    def __init__(self, proto, local_addr, local_port,
                 remote_addr, remote_port, state, pid):
        self.proto = proto
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.state = state
        self.pid = pid

    def to_dict(self):
        return {
            "proto": self.proto,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "state": self.state,
            "pid": self.pid,
        }


class ProcessInfo:
    """Details about the process that owns a connection."""

    __slots__ = ("pid", "name", "path", "start_time", "session", "mem")

    def __init__(self, pid, name="", path="", start_time="",
                 session="", mem=""):
        self.pid = pid
        self.name = name
        self.path = path
        self.start_time = start_time
        self.session = session
        self.mem = mem

    def to_dict(self):
        return {
            "pid": self.pid,
            "name": self.name,
            "path": self.path,
            "start_time": self.start_time,
            "session": self.session,
            "mem": self.mem,
        }


# ---------------------------------------------------------------------------
# Windows implementation
# ---------------------------------------------------------------------------

def _win_parse_netstat(output):
    """Parse ``netstat -ano`` output into Connection objects.

    The header line may be in any locale; we detect rows by shape:
    leading whitespace, a protocol token, two address:port tokens
    (or *:*), a state word, and a trailing integer PID.
    """
    conns = []
    # Match:  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       540
    # Also:   UDP    0.0.0.0:500            *:*                                    1234
    row_re = re.compile(
        r"^\s*(TCP|UDP)\s+"
        r"([\d.:%\[\]a-fA-F]+):(\d+)\s+"
        r"([\d.:%\[\]a-fA-F*]+):(\d+|\*)\s+"
        r"([A-Z_]*\s*)"
        r"(\d+)\s*$",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        m = row_re.match(line)
        if not m:
            continue
        proto = m.group(1).upper()
        local_addr = m.group(2)
        local_port = int(m.group(3))
        remote_addr = m.group(4)
        remote_port_raw = m.group(5)
        remote_port = int(remote_port_raw) if remote_port_raw != "*" else 0
        state = m.group(6).strip() or "—"
        pid = int(m.group(7))
        conns.append(Connection(
            proto, local_addr, local_port,
            remote_addr, remote_port, state, pid,
        ))
    return conns


def _win_get_connections():
    """Return all network connections on Windows via ``netstat -ano``."""
    r = subprocess.run(
        ["netstat", "-ano"],
        capture_output=True,
        # netstat output uses the OEM code page on Windows; decode loosely.
        encoding="utf-8", errors="replace",
    )
    return _win_parse_netstat(r.stdout)


def _win_get_process_info(pid):
    """Look up a process on Windows via ``tasklist``.

    Returns a :class:`ProcessInfo`. Fields that cannot be obtained
    are left as empty strings.
    """
    if pid == 0:
        return ProcessInfo(pid, name="System Idle Process")
    r = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH", "/V"],
        capture_output=True,
        encoding="utf-8", errors="replace",
    )
    stdout = r.stdout.strip()
    if not stdout or stdout.startswith("INFO:"):
        # Process may have exited between netstat and tasklist.
        return ProcessInfo(pid, name="(exited)")

    reader = csv.reader(io.StringIO(stdout))
    row = next(reader, None)
    if not row or len(row) < 5:
        return ProcessInfo(pid, name="(unknown)")

    # tasklist /V /FO CSV columns:
    # 0 Image Name, 1 PID, 2 Session Name, 3 Session#, 4 Mem Usage,
    # 5 Status, 6 User Name, 7 CPU Time, 8 Window Title
    name = row[0]
    session = row[2] if len(row) > 2 else ""
    mem = row[4] if len(row) > 4 else ""

    # Try to get the full process path via ctypes.
    path = _win_get_process_path(pid)
    start_time = _win_get_process_start_time(pid)

    return ProcessInfo(
        pid, name=name, path=path,
        start_time=start_time, session=session, mem=mem,
    )


def _win_get_process_path(pid):
    """Best-effort process image path via the Windows API (ctypes)."""
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        buf = ctypes.create_unicode_buffer(260)
        size = wintypes.DWORD(260)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid,
        )
        if not handle:
            return ""
        try:
            ok = kernel32.QueryFullProcessImageNameW(
                handle, 0, buf, ctypes.byref(size),
            )
            if ok:
                return buf.value
            return ""
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return ""


def _win_get_process_start_time(pid):
    """Best-effort process creation time via the Windows API (ctypes)."""
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class FILETIME(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD),
            ]

        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid,
        )
        if not handle:
            return ""
        try:
            created = FILETIME()
            exited = FILETIME()
            kernel = FILETIME()
            user = FILETIME()
            ok = kernel32.GetProcessTimes(
                handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel),
                ctypes.byref(user),
            )
            if not ok:
                return ""
            # FILETIME is 100-nanosecond intervals since 1601-01-01.
            # Convert to Unix timestamp.
            epoch_diff = 11644473600  # seconds between 1601 and 1970
            raw = (created.dwHighDateTime << 32) | created.dwLowDateTime
            unix_seconds = raw / 1e7 - epoch_diff
            dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
            return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Linux implementation
# ---------------------------------------------------------------------------

def _linux_parse_proc_net(path, proto):
    """Parse /proc/net/tcp or /proc/net/udp into Connection objects."""
    conns = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return conns

    # State codes from /proc/net/tcp
    states = {
        "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
        "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
        "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
        "0A": "LISTEN", "0B": "CLOSING",
    }

    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]   # 00000000:1F90
        remote = parts[2]  # 00000000:0000
        state_code = parts[3]
        inode = parts[9]

        local_ip_hex, local_port_hex = local.split(":")
        remote_ip_hex, remote_port_hex = remote.split(":")

        local_port = int(local_port_hex, 16)
        remote_port = int(remote_port_hex, 16) if remote_port_hex != "0000" else 0
        state = states.get(state_code, state_code)

        # Convert hex IP to dotted decimal
        local_addr = _hex_to_ip(local_ip_hex)
        remote_addr = _hex_to_ip(remote_ip_hex)

        # Find PID by searching /proc/*/fd for the socket inode
        pid = _linux_find_pid_by_inode(inode)
        conns.append(Connection(
            proto, local_addr, local_port,
            remote_addr, remote_port, state, pid,
        ))
    return conns


def _hex_to_ip(hex_ip):
    """Convert a little-endian hex IP from /proc/net/tcp to dotted decimal."""
    try:
        addr = int(hex_ip, 16)
        # /proc/net/tcp stores IPs in little-endian hex
        return f"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"
    except (ValueError, IndexError):
        return hex_ip


def _linux_find_pid_by_inode(inode):
    """Search /proc/*/fd/* for a socket matching the given inode."""
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            fd_dir = f"/proc/{pid_dir}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        target = os.readlink(f"{fd_dir}/{fd}")
                    except (OSError, PermissionError):
                        continue
                    if target.startswith("socket:[") and target.endswith("]"):
                        sock_inode = target[8:-1]
                        if sock_inode == inode:
                            return int(pid_dir)
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        pass
    return 0


def _linux_get_connections():
    """Return all network connections on Linux."""
    conns = []
    conns.extend(_linux_parse_proc_net("/proc/net/tcp", "TCP"))
    conns.extend(_linux_parse_proc_net("/proc/net/tcp6", "TCP6"))
    conns.extend(_linux_parse_proc_net("/proc/net/udp", "UDP"))
    conns.extend(_linux_parse_proc_net("/proc/net/udp6", "UDP6"))
    return conns


def _linux_get_process_info(pid):
    """Look up a process on Linux via /proc."""
    if pid == 0:
        return ProcessInfo(pid, name="(no process)")

    info = ProcessInfo(pid)
    try:
        # Process name (from /proc/PID/comm)
        with open(f"/proc/{pid}/comm") as f:
            info.name = f.read().strip()
    except (OSError, PermissionError, FileNotFoundError):
        info.name = "(unknown)"

    try:
        # Full command line
        with open(f"/proc/{pid}/cmdline") as f:
            cmdline = f.read().strip()
            info.path = cmdline.replace("\x00", " ") if cmdline else info.name
    except (OSError, PermissionError, FileNotFoundError):
        pass

    try:
        # Start time (from /proc/PID/stat, field 22 = starttime in clock ticks)
        with open(f"/proc/{pid}/stat") as f:
            stat_parts = f.read().split()
            starttime_ticks = int(stat_parts[21])
            clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
            boot_time = 0
            with open("/proc/stat") as sf:
                for line in sf:
                    if line.startswith("btime "):
                        boot_time = int(line.split()[1])
                        break
            start_epoch = boot_time + starttime_ticks / clk_tck
            dt = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
            info.start_time = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, PermissionError, FileNotFoundError, IndexError, ValueError):
        pass

    return info


# ---------------------------------------------------------------------------
# macOS implementation (lsof fallback)
# ---------------------------------------------------------------------------

def _mac_get_connections():
    """Return all network connections on macOS via ``lsof``."""
    conns = []
    try:
        r = subprocess.run(
            ["lsof", "-i", "-P", "-n"],
            capture_output=True, encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        return conns

    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        cmd = parts[0]
        pid = int(parts[1]) if parts[1].isdigit() else 0
        name_field = parts[-1]  # e.g. *:3000 (LISTEN)
        # Parse the name field: local->remote or *:port (LISTEN)
        m = re.match(r"([\d.]+):(\d+)(?:->([\d.]+):(\d+))?\s*\(?(\w+)?\)?", name_field)
        if not m:
            continue
        local_addr = m.group(1) or "*"
        local_port = int(m.group(2))
        remote_addr = m.group(3) or "0.0.0.0"
        remote_port = int(m.group(4)) if m.group(4) else 0
        state = m.group(5) or "—"
        proto = "TCP" if "TCP" in " ".join(parts) else "UDP"
        conns.append(Connection(
            proto, local_addr, local_port,
            remote_addr, remote_port, state, pid,
        ))
    return conns


def _mac_get_process_info(pid):
    """Look up a process on macOS via ``ps``."""
    if pid == 0:
        return ProcessInfo(pid, name="(no process)")
    info = ProcessInfo(pid)
    try:
        r = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm=,lstart="],
            capture_output=True, encoding="utf-8", errors="replace",
        )
        parts = r.stdout.strip().rsplit(None, 1)
        if len(parts) == 2:
            info.name = os.path.basename(parts[0])
            info.path = parts[0]
            info.start_time = parts[1]
        elif parts:
            info.name = os.path.basename(parts[0])
            info.path = parts[0]
    except Exception:
        info.name = "(unknown)"
    return info


# ---------------------------------------------------------------------------
# Platform dispatch
# ---------------------------------------------------------------------------

_PLATFORM = platform.system()


def get_connections():
    """Return all network connections on the current platform."""
    if _PLATFORM == "Windows":
        return _win_get_connections()
    elif _PLATFORM == "Linux":
        return _linux_get_connections()
    elif _PLATFORM == "Darwin":
        return _mac_get_connections()
    else:
        raise OSError(f"Unsupported platform: {_PLATFORM}")


def get_process_info(pid):
    """Return :class:`ProcessInfo` for *pid* on the current platform."""
    if _PLATFORM == "Windows":
        return _win_get_process_info(pid)
    elif _PLATFORM == "Linux":
        return _linux_get_process_info(pid)
    elif _PLATFORM == "Darwin":
        return _mac_get_process_info(pid)
    else:
        raise OSError(f"Unsupported platform: {_PLATFORM}")


# ---------------------------------------------------------------------------
# Filtering and rendering
# ---------------------------------------------------------------------------

def filter_by_port(conns, port, include_all=False):
    """Keep connections whose local or remote port equals *port*.

    By default only connections that "own" the port are returned:
    TCP rows in LISTENING/LISTEN state, plus UDP rows (which have no
    connection state — the placeholder "—" means a bound socket).
    When *include_all* is true, every state is kept.
    """
    listening_states = {"LISTENING", "LISTEN", "—"}
    result = []
    for c in conns:
        if c.local_port != port and c.remote_port != port:
            continue
        if not include_all and c.state.upper() not in listening_states:
            continue
        result.append(c)
    return result


def render_text(conns, port, explain=False):
    """Render matching connections as human-readable text."""
    if not conns:
        lines = [
            f"Port {port}: no matching connection found.",
            "",
            "Checked: TCP listeners and bound UDP sockets.",
            "Use --all to include established, time_wait, and other states.",
        ]
        return "\n".join(lines)

    lines = [f"Port {port}: {len(conns)} connection(s)", ""]

    # Cache process info per PID to avoid repeated lookups.
    pid_cache = {}

    for i, c in enumerate(conns, 1):
        if c.pid and c.pid not in pid_cache:
            pid_cache[c.pid] = get_process_info(c.pid)
        proc = pid_cache.get(c.pid)

        lines.append(f"  [{i}] {c.proto}  PID {c.pid}")
        lines.append(f"      local   {c.local_addr}:{c.local_port}")
        if c.remote_port:
            lines.append(f"      remote  {c.remote_addr}:{c.remote_port}")
        lines.append(f"      state   {c.state}")

        if proc:
            if proc.name and proc.name != "(exited)":
                lines.append(f"      process {proc.name}")
            elif proc.name:
                lines.append(f"      process {proc.name}")
            if proc.path:
                lines.append(f"      path    {proc.path}")
            if proc.start_time:
                lines.append(f"      started {proc.start_time}")
            if proc.mem:
                lines.append(f"      memory  {proc.mem}")
        else:
            lines.append("      process (no PID)")

        if explain:
            lines.append(f"      source  netstat row → tasklist PID filter"
                        f" → {'OpenProcess+QueryFullProcessImageNameW'
                              if _PLATFORM == 'Windows'
                              else '/proc/' + str(c.pid) + '/{comm,cmdline,stat}'}")
        lines.append("")

    return "\n".join(lines)


def render_json(conns, port):
    """Render matching connections as JSON."""
    pid_cache = {}
    results = []
    for c in conns:
        if c.pid and c.pid not in pid_cache:
            pid_cache[c.pid] = get_process_info(c.pid)
        proc = pid_cache.get(c.pid)
        entry = c.to_dict()
        entry["process"] = proc.to_dict() if proc else None
        results.append(entry)
    return json.dumps({
        "port": port,
        "count": len(results),
        "connections": results,
    }, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="portwho",
        description="Find which process is using a network port.",
    )
    p.add_argument("port", type=int, help="port number to look up (1-65535)")
    p.add_argument("--all", action="store_true",
                   help="include all states, not just LISTENING")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="machine-readable JSON output")
    p.add_argument("--explain", action="store_true",
                   help="show how each field was obtained")
    p.add_argument("--tcp", action="store_true",
                   help="TCP connections only")
    p.add_argument("--udp", action="store_true",
                   help="UDP connections only")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.port < 1 or args.port > 65535:
        print(f"portwho: port must be 1-65535, got {args.port}",
              file=sys.stderr)
        return 2

    try:
        all_conns = get_connections()
    except Exception as e:
        print(f"portwho: cannot read network table: {e}",
              file=sys.stderr)
        return 2

    # Protocol filter
    if args.tcp:
        all_conns = [c for c in all_conns if c.proto.upper().startswith("TCP")]
    if args.udp:
        all_conns = [c for c in all_conns if c.proto.upper().startswith("UDP")]

    matches = filter_by_port(all_conns, args.port, include_all=args.all)

    if args.as_json:
        print(render_json(matches, args.port))
    else:
        print(render_text(matches, args.port, explain=args.explain))

    if not matches:
        return 2
    # Check if any match has a resolved process
    has_process = any(c.pid != 0 for c in matches)
    return 0 if has_process else 1


if __name__ == "__main__":
    sys.exit(main())
