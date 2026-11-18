# portwho

**Who has that port? One number in, the process behind it out.**

`portwho` answers the question every developer hits: "something is already
listening on port 3000 — what is it?" Give it a port number and it prints the
protocol, local/remote address, connection state, PID, process name, executable
path, start time and memory use. No flags, no config, no dependencies — just the
standard library.

## Why

`netstat -ano` tells you the PID but stops there. Then you open task manager,
search the PID, squint at a name like `svchost.exe`, and still have no idea which
service it is or when it started. `portwho` closes that loop in one command, and
prints enough context to decide whether it is safe to stop the process.

It is deliberately read-only. It never kills anything, never changes a rule,
never writes a file. It only explains.

## Install

Copy `portwho.py` anywhere on your `PATH`, or run it in place:

```sh
python portwho.py 3000
```

Requires Python 3.8+. Works on Windows (via `netstat` + `tasklist` and the
Windows API), Linux (via `/proc/net/tcp*`), and macOS (via `lsof`). Only the
standard library is used.

## Usage

```sh
python portwho.py 80                 # who is listening on port 80?
python portwho.py 3000 --all         # include established / time_wait too
python portwho.py 443 --all --tcp    # only TCP, all states
python portwho.py 500 --udp          # only UDP
python portwho.py 3000 --json        # machine-readable output
python portwho.py 3000 --explain     # show where each field came from
```

### Port 80 — two listeners

```text
$ python portwho.py 80
Port 80: 2 connection(s)

  [1] TCP  PID 4
      local   0.0.0.0:80
      state   LISTENING
      process System
      memory  228 K

  [2] TCP  PID 4
      local   [::]:80
      state   LISTENING
      process System
      memory  228 K
```

Both IPv4 and IPv6 listeners are shown, and both belong to the same PID — the
process is looked up once and reused, not queried twice.

### A user process, fully identified

Start a small listener, then look it up — path, start time and memory all
resolved, because the process belongs to the current user:

```text
$ python portwho.py 18421 --explain
Port 18421: 1 connection(s)

  [1] TCP  PID 10984
      local   127.0.0.1:18421
      state   LISTENING
      process listener.exe
      path    C:\Users\Administrator\portwho-demo\listener.exe
      started 2026-11-18 11:24:18
      memory  61,736 K
      source  netstat row → tasklist PID filter → OpenProcess+QueryFullProcessImageNameW
```

Same port, with an `--all` view after a client connects — the remote end and
its ephemeral source port appear too:

```text
$ python portwho.py 18421 --all
Port 18421: 3 connection(s)

  [1] TCP  PID 21100
      local   127.0.0.1:18421
      state   LISTENING
      process listener.exe
      path    C:\Users\Administrator\portwho-demo\listener.exe
      started 2026-11-18 11:25:35
      memory  63,084 K

  [2] TCP  PID 21100
      local   127.0.0.1:18421
      remote  127.0.0.1:64140
      state   ESTABLISHED
      process listener.exe
      path    C:\Users\Administrator\portwho-demo\listener.exe
      started 2026-11-18 11:25:35
      memory  63,084 K

  [3] TCP  PID 5576
      local   127.0.0.1:64140
      remote  127.0.0.1:18421
      state   ESTABLISHED
      process listener.exe
      path    C:\Users\Administrator\portwho-demo\listener.exe
      started 2026-11-18 11:25:41
      memory  22,776 K
```

### Nothing on the port

```text
$ python portwho.py 45678
Port 45678: no matching connection found.

Checked: TCP listeners and bound UDP sockets.
Use --all to include established, time_wait, and other states.

$ echo $?
2
```

### Where the fields came from

```text
$ python portwho.py 80 --explain
Port 80: 2 connection(s)

  [1] TCP  PID 4
      local   0.0.0.0:80
      state   LISTENING
      process System
      memory  228 K
      source  netstat row → tasklist PID filter → OpenProcess+QueryFullProcessImageNameW
```

### JSON for scripts

```text
$ python portwho.py 135 --json
{
  "port": 135,
  "count": 2,
  "connections": [
    {
      "proto": "TCP",
      "local_addr": "0.0.0.0",
      "local_port": 135,
      "remote_addr": "0.0.0.0",
      "remote_port": 0,
      "state": "LISTENING",
      "pid": 540,
      "process": {
        "pid": 540,
        "name": "svchost.exe",
        "path": "",
        "start_time": "",
        "session": "Services",
        "mem": "16,240 K"
      }
    }
  ]
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | at least one connection found, with a real PID |
| 1 | connections found, but none carries a PID (e.g. only `TIME_WAIT`) |
| 2 | no connection on that port, or an invalid port number |

This makes it usable as a CI gate: a non-zero code means "port is free" (2) or
"cannot attribute it" (1), and 0 means "something real owns it".

## Design decisions

**Only ports that are actually owned, by default.** A client connection to a
remote `:443` is not "using port 443" in the sense a developer cares about —
the local ephemeral port is. So the default view keeps TCP listeners and bound
UDP sockets, and hides everything else behind `--all`. Otherwise asking about
port 443 on a normal machine returns hundreds of irrelevant browser rows.

**UDP has no state, so its placeholder counts as listening.** A UDP row from
`netstat` carries an empty state field. Treating that as "not listening" would
hide every bound UDP socket by default — precisely the case you want to see.
The placeholder is therefore included in the default filter, and shown as `—`
rather than a fake `LISTENING`.

**Resolve each PID once.** One listener often appears twice (IPv4 and IPv6).
The process lookup goes through a per-run cache, so a port with twenty rows
still performs one `tasklist` query per distinct PID, not twenty.

**Best-effort fields stay optional.** Executable path and start time come from
the Windows API and can be denied for processes owned by another user. When
that happens the tool prints the fields it does have and leaves the rest blank,
instead of failing or guessing. A blank `path` means "not permitted", not "no
such process".

**Localized headers never parsed.** The `netstat` header line changes with the
system locale (and is not even readable as UTF-8 on a Chinese Windows install).
Rows are matched by shape — protocol token, two `address:port` pairs, a state
word, a trailing integer PID — so the tool does not care what language the
header is printed in.

## Tests

```sh
python -m unittest discover -s tests
```

44 tests, all passing. They cover `netstat` parsing (including IPv6, UDP with no
state, `TIME_WAIT` with PID 0, and junk lines), port filtering, hex-to-IP
conversion, text and JSON rendering, argument parsing, protocol filters, exit
codes, and the per-PID lookup cache.

## License

MIT. See [LICENSE](LICENSE).
