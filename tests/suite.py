#!/usr/bin/env python3
"""
Portable test suite for traceroute.py (Windows, Linux, macOS, FreeBSD, OpenBSD, ...).

Run from the repository root with elevated rights (raw sockets):

    sudo python3 tests/suite.py            # Linux / macOS / BSD
    python tests/suite.py                  # Windows (elevated terminal)
    python3 tests/suite.py path/to/traceroute.py

Tests are of two kinds:
  REQUIRED       must pass; the exit code is 1 if any fails. Loopback only, so
                 they do not depend on the network of the test machine.
  INFORMATIONAL  depend on the network, IPv6, or platform features; failures are
                 reported (with output) but do not fail the run.

Windows: ICMP mode (-I) uses the Windows ICMP API, TCP mode needs no raw receive,
so those are required. UDP mode, raw ICMP (-e, -s, -g, -i, --raw) and IPv6 need raw
sockets, and raw sockets do not reliably see loopback traffic on Windows, so those
tests are informational there.

If $GITHUB_STEP_SUMMARY is set, a Markdown summary is appended to it.
"""
import os
import platform
import re
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "traceroute.py"

LO = "127.0.0.1"
HOP = r"^\s*1\s+127\.0\.0\.1\s+[\d.]+ ms"          # a hop line for loopback
SYS = sys.platform
WIN = os.name == "nt"

results = []   # (status, required, name, args)
details = {}   # name -> command output of failed tests (shown in the job summary)


def is_admin():
    if WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def run(args, user=None, timeout=120):
    cmd = [sys.executable, str(SCRIPT)] + args
    kw = {}
    if user is not None and not WIN:
        kw["preexec_fn"] = lambda: (os.setgid(user[1]), os.setuid(user[0]))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace", **kw)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def test(name, args, required=True, rc=0, must=(), mustnot=(), user=None):
    code, out = run(args, user=user)
    ok = (code == rc
          and all(re.search(m, out, re.M) for m in must)
          and not any(re.search(m, out, re.M) for m in mustnot))
    results.append(("PASS" if ok else "FAIL", required, name, " ".join(args)))
    if not ok:
        details[name] = f"$ traceroute.py {' '.join(args)}   (exit code {code}, expected {rc})\n{out[:1500]}"
        kind = "REQUIRED" if required else "info"
        print(f"--- FAIL ({kind}) {name}: rc={code}, expected rc={rc}\n"
              f"    args: {' '.join(args)}\n    " + out[:700].replace("\n", "\n    "))


def skip(name, why, required=False):
    results.append(("SKIP", required, name, why))
    print(f"--- SKIP {name}: {why}")


def loopback_interface():
    """Interface argument that exists on this machine: a name, or an index on Windows."""
    if WIN:
        try:
            return str(socket.if_nameindex()[0][0])
        except (OSError, AttributeError, IndexError):
            return "1"
    return "lo" if SYS.startswith("linux") else "lo0"


def main():
    print(f"platform : {platform.platform()} ({SYS})")
    print(f"python   : {sys.version.split()[0]}")
    print(f"elevated : {is_admin()}")
    print(f"script   : {SCRIPT}\n")
    if not is_admin():
        print("WARNING: not running elevated; raw-socket tests will fail.\n")

    # On Windows tests that need raw-socket reception on loopback are informational.
    raw = not WIN
    # On Windows, generic option tests use ICMP mode (the Windows ICMP API).
    M = ["-I"] if WIN else []
    base = ["-n", "-m", "3", "-q", "2", "-w", "1"]
    info = False

    # ------------------------------------------------------------ REQUIRED --
    test("version", ["-V"], must=[r"traceroute\.py"])
    test("help", ["--help"], must=[r"usage"])
    modes = [("ICMP -I", ["-I"], True), ("UDP -U", ["-U"], raw), ("default", [], raw),
             ("TCP -T", ["-T", "-p", "9"], True), ("-M icmp", ["-M", "icmp"], True),
             ("-M udp", ["-M", "udp"], raw), ("-M tcp", ["-M", "tcp", "-p", "9"], True)]
    for label, mode, req in modes:
        test(f"mode {label}", mode + base + [LO], required=req, must=[HOP])
    test("-q 1", M + ["-q", "1", "-n", "-w", "1", LO], must=[r"^\s*1\s+127\.0\.0\.1\s+[\d.]+ ms$"])
    test("-N 1", M + ["-N", "1"] + base + [LO], must=[HOP])
    test("-f 1 -m 3", M + ["-f", "1", "-m", "3", "-n", "-w", "1", LO], must=[HOP])
    test("-z 0.01", M + ["-z", "0.01"] + base + [LO], must=[HOP])
    test("-w 0.5", M + ["-w", "0.5", "-m", "3", "-n", LO], must=[HOP])
    test("-p udp", ["-p", "40000"] + base + [LO], required=raw, must=[HOP])
    test("-s 127.0.0.1", ["-s", LO] + M + base + [LO], required=raw, must=[HOP])
    test("-t 16", M + ["-t", "16"] + base + [LO], must=[HOP])
    test("-F", M + ["-F"] + base + [LO], must=[HOP])
    test("-4", M + ["-4"] + base + [LO], must=[HOP])
    test("-e", ["-e"] + M + base + [LO], required=raw, must=[HOP])
    test("packet length 100", M + base + [LO, "100"], must=[r"100 byte packets", HOP])
    test("names (localhost)", M + ["-m", "3", "-q", "2", "-w", "1", "localhost"],
         required=raw, must=[r"1\s+\S+ \(127\.0\.0\.1\)"])
    test("error: -4 -6", ["-4", "-6", "x"], rc=1, must=[r"only one of -4, -6"])
    test("error: -I -T", ["-I", "-T", LO], rc=1, must=[r"only one of"])
    test("error: unknown host", ["no-such-host.invalid"], rc=1, must=[r"unknown host"])
    test("error: bad tos", ["-t", "300", LO], rc=1, must=[r"tos must be"])
    test("error: -m 0", ["-m", "0", LO], rc=1, must=[r"invalid option"])
    test("error: no host", [], rc=1, must=[r"host"])
    test("error: -g with -6", ["-6", "-g", "1.1.1.1", "::1"], rc=1, must=[r"only supported for IPv4"])
    test("error: -l with IPv4", ["-l", "5", LO], rc=1, must=[r"requires IPv6"])
    test("error: bad interface", ["-i", "nosuchdev0", LO], rc=1,
         must=[r"cannot use interface|not supported on this platform|unknown interface"])

    # ------------------------------------------------------- INFORMATIONAL --
    test("-N 2 -q 4", M + ["-N", "2", "-q", "4", "-n", "-m", "3", "-w", "1", LO],
         required=info, must=[HOP])
    test("-z 20 (ms)", M + ["-z", "20", "-q", "2", "-n", "-m", "3", "-w", "1", LO],
         required=info, must=[HOP])
    test("packet length 1400", M + base + [LO, "1400"], required=info,
         must=[r"1400 byte packets", HOP])

    # -g (loose source route): Linux delivers it; macOS/BSD drop such packets by default
    # (silent stars) or refuse to send ("Permission denied"); Windows may do either.
    # Both are acceptable; a crash is not.
    code, out = run(["-g", LO, "-I", "-n", "-m", "3", "-q", "1", "-w", "1", LO])
    g_ok = ("Traceback" not in out and
            ((code == 0 and re.search(r"^\s*1\s+(127\.0\.0\.1\s+[\d.]+ ms|\*)", out, re.M))
             or (code == 1 and re.search(r"sendto: (Permission denied|Operation not permitted)", out))))
    results.append(("PASS" if g_ok else "FAIL", info, "-g loopback (delivered or cleanly blocked)", "-g"))
    if not g_ok:
        details["-g loopback"] = f"exit code {code}\n{out[:1500]}"
        print(f"--- FAIL (info) -g loopback: rc={code}\n    " + out[:700].replace("\n", "\n    "))

    for label, mode in [("UDP", []), ("ICMP", ["-I"]), ("TCP", ["-T", "-p", "9"])]:
        test(f"--mtu {label}", ["--mtu"] + mode + base + [LO], required=info, must=[r"F=\d+"])
    test("--mtu explicit size", ["--mtu"] + M + base + [LO, "1400"], required=info, must=[r"F=1400"])

    iface = loopback_interface()
    if SYS.startswith(("linux", "darwin", "win")) or WIN:
        test(f"-i {iface}", ["-i", iface] + M + base + [LO], required=info, must=[HOP])
    else:   # FreeBSD, OpenBSD, ...: -i is unsupported by design and must say so cleanly
        test(f"-i {iface} (unsupported: clean error)", ["-i", iface] + base + [LO],
             required=info, rc=1, must=[r"not supported on this platform"])

    test("-A (AS lookup, private address)", ["-A"] + M + base + [LO], required=info,
         must=[r"^\s*1\s+127\.0\.0\.1 \[\*\]\s+[\d.]+ ms"])
    test("-A with names", ["-A"] + M + ["-m", "3", "-q", "2", "-w", "1", "localhost"],
         required=info, must=[r"\(127\.0\.0\.1\) \[\*\]"])
    test("--mtu + -F + -t together", ["--mtu", "-t", "8"] + M + base + [LO], required=info,
         must=[r"F=\d+"])

    if WIN:   # Windows-only switches
        test("--raw (ICMP via raw sockets)", ["-I", "--raw"] + base + [LO], required=info, must=[HOP])
        test("--rcvall 1 (UDP)", ["-U", "--rcvall", "1"] + base + [LO], required=info, must=[HOP])
        test("--rcvall 3 (UDP)", ["-U", "--rcvall", "3"] + base + [LO], required=info, must=[HOP])
        test("--debug (ICMP API)", ["-I", "--debug"] + base + [LO], required=info, must=[HOP])

    # IPv6 loopback
    for label, mode in [("UDP", []), ("ICMP", ["-I"]), ("TCP", ["-T", "-p", "9"])]:
        test(f"IPv6 {label} ::1", ["-6"] + mode + base + ["::1"], required=info,
             must=[r"^\s*1\s+::1\s+[\d.]+ ms"])

    # Real network (may be filtered on CI runners). Any hop within the first four that
    # answers counts (hop 1 may be silent on CI runners).
    real = ["-n", "-m", "4", "-q", "2", "-w", "2", "8.8.8.8"]
    for label, mode in [("ICMP", ["-I"]), ("UDP", []), ("TCP", ["-T", "-p", "443"])]:
        test(f"real path {label} (8.8.8.8)", mode + real, required=info,
             must=[r"^\s*\d+\s+(\*\s+)*\d+\.\d+\.\d+\.\d+\s+[\d.]+ ms"])
    test("real path names", M + ["-m", "2", "-q", "1", "-w", "2", "8.8.8.8"], required=info,
         must=[r"\(\d+\.\d+\.\d+\.\d+\)"])

    # Unprivileged run must fail with a helpful message
    if not WIN and hasattr(os, "setuid") and os.geteuid() == 0:
        try:
            import pwd
            pw = pwd.getpwnam("nobody")
            test("non-root gives helpful error", base + [LO], required=info, rc=1,
                 must=[r"raw sockets need elevated rights"], user=(pw.pw_uid, pw.pw_gid))
        except Exception as e:                       # no 'nobody' user etc.
            skip("non-root gives helpful error", str(e))
    else:
        skip("non-root gives helpful error", "not applicable on this platform / not root")

    # -------------------------------------------------------------- report --
    p = sum(1 for s, *_ in results if s == "PASS")
    f_req = [r for r in results if r[0] == "FAIL" and r[1]]
    f_info = [r for r in results if r[0] == "FAIL" and not r[1]]
    sk = [r for r in results if r[0] == "SKIP"]
    print("\n" + "=" * 60)
    print(f"{p} passed, {len(f_req)} REQUIRED failed, {len(f_info)} informational failed, "
          f"{len(sk)} skipped, {len(results)} total")
    for s, req, name, args in results:
        tag = ("REQ " if req else "info") if s != "SKIP" else "    "
        print(f"  {s:4}  {tag}  {name}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"### traceroute.py on {platform.system()} {platform.release()} "
                     f"(Python {sys.version.split()[0]})\n\n")
            fh.write(f"**{p} passed**, {len(f_req)} required failed, "
                     f"{len(f_info)} informational failed, {len(sk)} skipped\n\n")
            fh.write("| Result | Kind | Test |\n|---|---|---|\n")
            for s, req, name, args in results:
                kind = "required" if req else "info"
                fh.write(f"| {s} | {kind} | `{name}` |\n")
            fh.write("\n")
            if details:
                fh.write("#### Output of failed tests\n\n")
                for name, text in details.items():
                    fh.write(f"<details><summary>{name}</summary>\n\n```\n{text}\n```\n\n</details>\n\n")

    return 1 if f_req else 0


if __name__ == "__main__":
    sys.exit(main())
