"""Tests for portwho."""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Make portwho importable regardless of cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import portwho


class TestConnectionModel(unittest.TestCase):
    """Connection and ProcessInfo data classes."""

    def test_connection_to_dict(self):
        c = portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0, "LISTENING", 4)
        d = c.to_dict()
        self.assertEqual(d["proto"], "TCP")
        self.assertEqual(d["local_port"], 80)
        self.assertEqual(d["pid"], 4)

    def test_connection_to_dict_udp(self):
        c = portwho.Connection("UDP", "0.0.0.0", 500, "0.0.0.0", 0, "—", 1234)
        d = c.to_dict()
        self.assertEqual(d["proto"], "UDP")
        self.assertEqual(d["state"], "—")

    def test_process_info_defaults(self):
        p = portwho.ProcessInfo(0)
        self.assertEqual(p.pid, 0)
        self.assertEqual(p.name, "")
        self.assertEqual(p.path, "")

    def test_process_info_to_dict(self):
        p = portwho.ProcessInfo(42, name="test", path="/bin/test",
                                start_time="2026-01-01 00:00:00")
        d = p.to_dict()
        self.assertEqual(d["pid"], 42)
        self.assertEqual(d["name"], "test")
        self.assertEqual(d["path"], "/bin/test")


class TestWinNetstatParse(unittest.TestCase):
    """Parsing netstat -ano output on Windows."""

    SAMPLE = """\

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       540
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    10.0.0.1:139           0.0.0.0:0              LISTENING       4
  TCP    10.0.0.1:54773         10.0.0.2:53            TIME_WAIT       0
  TCP    10.0.0.1:54782         10.0.0.3:443           ESTABLISHED     1780
  UDP    0.0.0.0:500            *:*                                    1234
  UDP    0.0.0.0:4500           *:*                                    1234
"""

    def test_parse_count(self):
        conns = portwho._win_parse_netstat(self.SAMPLE)
        self.assertEqual(len(conns), 8)

    def test_parse_tcp_listening(self):
        conns = portwho._win_parse_netstat(self.SAMPLE)
        first = conns[0]
        self.assertEqual(first.proto, "TCP")
        self.assertEqual(first.local_addr, "0.0.0.0")
        self.assertEqual(first.local_port, 80)
        self.assertEqual(first.state, "LISTENING")
        self.assertEqual(first.pid, 4)

    def test_parse_tcp_established(self):
        conns = portwho._win_parse_netstat(self.SAMPLE)
        est = [c for c in conns if c.state == "ESTABLISHED"]
        self.assertEqual(len(est), 1)
        self.assertEqual(est[0].local_port, 54782)
        self.assertEqual(est[0].remote_port, 443)
        self.assertEqual(est[0].remote_addr, "10.0.0.3")

    def test_parse_udp_no_state(self):
        conns = portwho._win_parse_netstat(self.SAMPLE)
        udps = [c for c in conns if c.proto == "UDP"]
        self.assertEqual(len(udps), 2)
        self.assertEqual(udps[0].local_port, 500)
        self.assertEqual(udps[0].remote_addr, "*")
        self.assertEqual(udps[0].remote_port, 0)
        # UDP rows have empty state field — becomes placeholder.
        self.assertEqual(udps[0].state, "—")

    def test_parse_time_wait_pid_zero(self):
        conns = portwho._win_parse_netstat(self.SAMPLE)
        tw = [c for c in conns if c.state == "TIME_WAIT"]
        self.assertEqual(len(tw), 1)
        self.assertEqual(tw[0].pid, 0)

    def test_parse_empty_input(self):
        conns = portwho._win_parse_netstat("")
        self.assertEqual(conns, [])

    def test_parse_garbage_lines_ignored(self):
        output = "random text\nnot a connection line\nTCP    0.0.0.0:80  0.0.0.0:0  LISTENING  4\n"
        conns = portwho._win_parse_netstat(output)
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].local_port, 80)

    def test_parse_ipv6_address(self):
        output = "  TCP    [::]:80             [::]:0              LISTENING       4\n"
        conns = portwho._win_parse_netstat(output)
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].local_addr, "[::]")
        self.assertEqual(conns[0].local_port, 80)


class TestFilterByPort(unittest.TestCase):
    """Port filtering logic."""

    def setUp(self):
        self.conns = [
            portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0, "LISTENING", 4),
            portwho.Connection("TCP", "0.0.0.0", 443, "0.0.0.0", 0, "LISTENING", 4),
            portwho.Connection("TCP", "10.0.0.1", 54782, "10.0.0.3", 443, "ESTABLISHED", 1780),
            portwho.Connection("TCP", "10.0.0.1", 54783, "10.0.0.3", 443, "TIME_WAIT", 0),
        ]

    def test_filter_listening_only(self):
        result = portwho.filter_by_port(self.conns, 80)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].local_port, 80)

    def test_filter_all_states(self):
        result = portwho.filter_by_port(self.conns, 443, include_all=True)
        self.assertEqual(len(result), 3)

    def test_filter_listening_excludes_established(self):
        result = portwho.filter_by_port(self.conns, 443)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].state, "LISTENING")

    def test_filter_no_match(self):
        result = portwho.filter_by_port(self.conns, 9999)
        self.assertEqual(result, [])

    def test_filter_remote_port(self):
        """--all should also match connections where the remote port matches."""
        result = portwho.filter_by_port(self.conns, 443, include_all=True)
        # 1 LISTENING on 443 + 2 established/time_wait with remote 443
        states = [c.state for c in result]
        self.assertIn("LISTENING", states)
        self.assertIn("ESTABLISHED", states)


class TestHexToIp(unittest.TestCase):
    """Linux /proc/net/tcp hex-to-IP conversion."""

    def test_zero(self):
        self.assertEqual(portwho._hex_to_ip("00000000"), "0.0.0.0")

    def test_loopback(self):
        # 127.0.0.1 in little-endian hex = 0100007F
        self.assertEqual(portwho._hex_to_ip("0100007F"), "127.0.0.1")

    def test_class_b(self):
        # 10.0.0.1 in memory order is 0A 00 00 01 → little-endian hex 0100000A
        self.assertEqual(portwho._hex_to_ip("0100000A"), "10.0.0.1")

    def test_255_255_255_255(self):
        self.assertEqual(portwho._hex_to_ip("FFFFFFFF"), "255.255.255.255")


class TestRenderText(unittest.TestCase):
    """Text output rendering."""

    def test_render_no_match(self):
        out = portwho.render_text([], 9999)
        self.assertIn("9999", out)
        self.assertIn("no matching", out)
        self.assertIn("--all", out)

    def test_render_with_connection(self):
        c = portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0,
                               "LISTENING", 4)
        with patch.object(portwho, "get_process_info",
                          return_value=portwho.ProcessInfo(4, name="System")):
            out = portwho.render_text([c], 80)
        self.assertIn("Port 80", out)
        self.assertIn("PID 4", out)
        self.assertIn("LISTENING", out)
        self.assertIn("System", out)

    def test_render_explain(self):
        c = portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0,
                               "LISTENING", 4)
        with patch.object(portwho, "get_process_info",
                          return_value=portwho.ProcessInfo(4, name="System")):
            out = portwho.render_text([c], 80, explain=True)
        self.assertIn("source", out)

    def test_render_remote_addr_shown(self):
        c = portwho.Connection("TCP", "10.0.0.1", 54782, "10.0.0.3", 443,
                               "ESTABLISHED", 1780)
        with patch.object(portwho, "get_process_info",
                          return_value=portwho.ProcessInfo(1780, name="chrome.exe")):
            out = portwho.render_text([c], 54782)
        self.assertIn("remote", out)
        self.assertIn("10.0.0.3", out)
        self.assertIn("443", out)

    def test_render_remote_addr_hidden_when_zero(self):
        c = portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0,
                               "LISTENING", 4)
        with patch.object(portwho, "get_process_info",
                          return_value=portwho.ProcessInfo(4, name="System")):
            out = portwho.render_text([c], 80)
        # No "remote" line when remote_port is 0
        lines = out.splitlines()
        remote_lines = [l for l in lines if "remote" in l.lower()]
        self.assertEqual(len(remote_lines), 0)

    def test_render_process_path(self):
        c = portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0,
                               "LISTENING", 4)
        proc = portwho.ProcessInfo(4, name="System",
                                   path="C:\\Windows\\System32\\kernel.exe",
                                   start_time="2026-01-01 00:00:00",
                                   mem="228 K")
        with patch.object(portwho, "get_process_info", return_value=proc):
            out = portwho.render_text([c], 80)
        self.assertIn("path", out)
        self.assertIn("kernel.exe", out)
        self.assertIn("started", out)
        self.assertIn("2026-01-01", out)
        self.assertIn("memory", out)


class TestRenderJson(unittest.TestCase):
    """JSON output rendering."""

    def test_json_no_match(self):
        out = portwho.render_json([], 9999)
        import json
        d = json.loads(out)
        self.assertEqual(d["port"], 9999)
        self.assertEqual(d["count"], 0)
        self.assertEqual(d["connections"], [])

    def test_json_with_connection(self):
        c = portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0,
                               "LISTENING", 4)
        proc = portwho.ProcessInfo(4, name="System", mem="228 K")
        with patch.object(portwho, "get_process_info", return_value=proc):
            out = portwho.render_json([c], 80)
        import json
        d = json.loads(out)
        self.assertEqual(d["port"], 80)
        self.assertEqual(d["count"], 1)
        self.assertEqual(d["connections"][0]["proto"], "TCP")
        self.assertEqual(d["connections"][0]["process"]["name"], "System")
        self.assertEqual(d["connections"][0]["process"]["mem"], "228 K")


class TestArgparse(unittest.TestCase):
    """Command-line argument parsing."""

    def test_basic_port(self):
        args = portwho.build_parser().parse_args(["80"])
        self.assertEqual(args.port, 80)
        self.assertFalse(args.all)
        self.assertFalse(args.explain)

    def test_all_flag(self):
        args = portwho.build_parser().parse_args(["80", "--all"])
        self.assertTrue(args.all)

    def test_json_flag(self):
        args = portwho.build_parser().parse_args(["80", "--json"])
        self.assertTrue(args.as_json)

    def test_explain_flag(self):
        args = portwho.build_parser().parse_args(["80", "--explain"])
        self.assertTrue(args.explain)

    def test_tcp_flag(self):
        args = portwho.build_parser().parse_args(["80", "--tcp"])
        self.assertTrue(args.tcp)

    def test_udp_flag(self):
        args = portwho.build_parser().parse_args(["80", "--udp"])
        self.assertTrue(args.udp)

    def test_tcp_and_udp_both(self):
        args = portwho.build_parser().parse_args(["80", "--tcp", "--udp"])
        self.assertTrue(args.tcp)
        self.assertTrue(args.udp)


class TestExitCodes(unittest.TestCase):
    """Exit code behavior."""

    def test_exit_no_match(self):
        with patch.object(portwho, "get_connections", return_value=[]):
            rc = portwho.main(["9999"])
        self.assertEqual(rc, 2)

    def test_exit_bad_port_zero(self):
        rc = portwho.main(["0"])
        self.assertEqual(rc, 2)

    def test_exit_bad_port_too_high(self):
        rc = portwho.main(["70000"])
        self.assertEqual(rc, 2)

    def test_exit_found_with_process(self):
        c = portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0,
                               "LISTENING", 4)
        with patch.object(portwho, "get_connections", return_value=[c]):
            with patch.object(portwho, "get_process_info",
                              return_value=portwho.ProcessInfo(4, name="System")):
                rc = portwho.main(["80"])
        self.assertEqual(rc, 0)

    def test_exit_found_no_pid(self):
        """Connection exists but PID is 0 (TIME_WAIT) — exit 1."""
        c = portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0,
                               "LISTENING", 0)
        with patch.object(portwho, "get_connections", return_value=[c]):
            with patch.object(portwho, "get_process_info",
                              return_value=portwho.ProcessInfo(0)):
                rc = portwho.main(["80"])
        self.assertEqual(rc, 1)


class TestPidCache(unittest.TestCase):
    """Process info is looked up once per PID, not per connection."""

    def test_duplicate_pids_single_lookup(self):
        conns = [
            portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0, "LISTENING", 4),
            portwho.Connection("TCP", "[::]", 80, "[::]", 0, "LISTENING", 4),
        ]
        mock_proc = portwho.ProcessInfo(4, name="System")
        with patch.object(portwho, "get_process_info",
                          return_value=mock_proc) as mock_fn:
            portwho.render_text(conns, 80)
        # Should be called once even though two connections share PID 4.
        self.assertEqual(mock_fn.call_count, 1)


class TestProtocolFilter(unittest.TestCase):
    """--tcp and --udp filters in main()."""

    def setUp(self):
        self.conns = [
            portwho.Connection("TCP", "0.0.0.0", 80, "0.0.0.0", 0, "LISTENING", 4),
            portwho.Connection("UDP", "0.0.0.0", 500, "0.0.0.0", 0, "—", 1234),
        ]

    def test_tcp_filter_excludes_udp(self):
        with patch.object(portwho, "get_connections", return_value=self.conns):
            with patch.object(portwho, "get_process_info",
                              return_value=portwho.ProcessInfo(4, name="test")):
                rc = portwho.main(["80", "--tcp"])
        self.assertEqual(rc, 0)

    def test_udp_filter_excludes_tcp(self):
        with patch.object(portwho, "get_connections", return_value=self.conns):
            with patch.object(portwho, "get_process_info",
                              return_value=portwho.ProcessInfo(1234, name="test")):
                rc = portwho.main(["500", "--udp"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
