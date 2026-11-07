#!/usr/bin/env python3
"""
Portable test suite for traceroute.py (Linux, macOS, FreeBSD, OpenBSD, ...).

Run from the repository root with elevated rights (raw sockets):

    sudo python3 tests/suite.py            # Linux / macOS / BSD
    python3 tests/suite.py path/to/traceroute.py

Tests are of two kinds:
  REQUIRED       must pass; the exit code is 1 if any fails. Loopback only, so
                 they do not depend on the network of the test machine.
  INFORMATIONAL  depend on the network, IPv6, or platform features; failures are
                 reported (with output) but do not fail the run.

If $GITHUB_STEP_SUMMARY is set, a Markdown summary is appended to it.
"""
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "traceroute.py"

LO = "127.0.0.1"
HOP = r"^\s*1\s+127\.0\.0\.1\s+[\d.]+ ms"          # a hop line for loopback
SYS = sys.platform
LO_IF = "lo" if SYS.startswith("linux") else "lo0"

results = []   # (status, required, name, args)


def run(args, user=None, timeout=90):
    cmd = [sys.executable, str(SCRIPT)] + args
    kw = {}
    if user is not None:
        kw["preexec_fn"] = lambda: (os.setgid(user[1]), os.setuid(user[0]))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
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
        kind = "REQUIRED" if required else "info"
        print(f"--- FAIL ({kind}) {name}: rc={code}, expected rc={rc}\n"
              f"    args: {' '.join(args)}\n    " + out[:700].replace("\n", "\n    "))


def skip(name, why, required=False):
    results.append(("SKIP", required, name, why))
    print(f"--- SKIP {name}: {why}")


def main():
    print(f"platform : {platform.platform()} ({SYS})")
    print(f"python   : {sys.version.split()[0]}")
    print(f"user     : uid={os.getuid()} euid={os.geteuid()}")
    print(f"script   : {SCRIPT}\n")
    if os.geteuid() != 0:
        print("WARNING: not running as root; raw-socket tests will fail.\n")

    base = ["-n", "-m", "3", "-q", "2", "-w", "1"]

    # ------------------------------------------------------------ REQUIRED --
    test("version", ["-V"], must=[r"traceroute\.py"])
    test("help", ["--help"], must=[r"usage"])
    for label, mode in [("ICMP -I", ["-I"]), ("UDP -U", ["-U"]), ("default", []),
                        ("TCP -T", ["-T", "-p", "9"]), ("-M icmp", ["-M", "icmp"]),
                        ("-M udp", ["-M", "udp"]), ("-M tcp", ["-M", "tcp", "-p", "9"])]:
        test(f"mode {label}", mode + base + [LO], must=[HOP])
    test("-q 1", ["-q", "1", "-n", "-w", "1", LO], must=[r"^\s*1\s+127\.0\.0\.1\s+[\d.]+ ms$"])
    test("-N 1", ["-N", "1"] + base + [LO], must=[HOP])
    test("-f 1 -m 3", ["-f", "1", "-m", "3", "-n", "-w", "1", LO], must=[HOP])
    test("-z 0.01", ["-z", "0.01"] + base + [LO], must=[HOP])
    test("-w 0.5", ["-w", "0.5", "-m", "3", "-n", LO], must=[HOP])
    test("-p udp", ["-p", "40000"] + base + [LO], must=[HOP])
    test("-s 127.0.0.1", ["-s", LO] + base + [LO], must=[HOP])
    test("-t 16", ["-t", "16"] + base + [LO], must=[HOP])
    test("-F", ["-F"] + base + [LO], must=[HOP])
    test("-4", ["-4"] + base + [LO], must=[HOP])
    test("-e", ["-e"] + base + [LO], must=[HOP])
    test("packet length 100", base + [LO, "100"], must=[r"100 byte packets", HOP])
    test("names (localhost)", ["-m", "3", "-q", "2", "-w", "1", "localhost"],
         must=[r"1\s+localhost \(127\.0\.0\.1\)"])
    test("error: -4 -6", ["-4", "-6", "x"], rc=1, must=[r"only one of -4, -6"])
    test("error: -I -T", ["-I", "-T", LO], rc=1, must=[r"only one of"])
    test("error: unknown host", ["no-such-host.invalid"], rc=1, must=[r"unknown host"])
    test("error: bad tos", ["-t", "300", LO], rc=1, must=[r"tos must be"])
    test("error: -m 0", ["-m", "0", LO], rc=1, must=[r"invalid option"])
    test("error: no host", [], rc=1, must=[r"host"])
    test("error: -g with -6", ["-6", "-g", "1.1.1.1", "::1"], rc=1, must=[r"only supported for IPv4"])
    test("error: -l with IPv4", ["-l", "5", LO], rc=1, must=[r"requires IPv6"])
    test("error: bad interface", ["-i", "nosuchdev0", LO], rc=1,
         must=[r"cannot use interface|not supported on this platform"])

    # ------------------------------------------------------- INFORMATIONAL --
    info = False
    test("-N 2 -q 4", ["-N", "2", "-q", "4", "-n", "-m", "3", "-w", "1", LO],
         required=info, must=[HOP])
    test("-z 20 (ms)", ["-z", "20", "-q", "2", "-n", "-m", "3", "-w", "1", LO],
         required=info, must=[HOP])
    test("packet length 1400", base + [LO, "1400"], required=info, must=[r"1400 byte packets", HOP])
    test("-g loopback", ["-g", LO, "-I", "-n", "-m", "3", "-q", "1", "-w", "1", LO],
         required=info, must=[HOP])
    for label, mode in [("UDP", []), ("ICMP", ["-I"]), ("TCP", ["-T", "-p", "9"])]:
        test(f"--mtu {label}", ["--mtu"] + mode + base + [LO], required=info, must=[r"F=\d+"])
    test("--mtu explicit size", ["--mtu"] + base + [LO, "1400"], required=info, must=[r"F=1400"])
    test(f"-i {LO_IF}", ["-i", LO_IF] + base + [LO], required=info, must=[HOP])
    test("-A (AS lookup, private address)", ["-A"] + base + [LO], required=info,
         must=[r"^\s*1\s+127\.0\.0\.1 \[\*\]\s+[\d.]+ ms"])
    test("-A with names", ["-A", "-m", "3", "-q", "2", "-w", "1", "localhost"],
         required=info, must=[r"localhost \(127\.0\.0\.1\) \[\*\]"])
    test("--mtu + -F + -t together", ["--mtu", "-t", "8"] + base + [LO], required=info, must=[r"F=\d+"])

    # IPv6 loopback
    for label, mode in [("UDP", []), ("ICMP", ["-I"]), ("TCP", ["-T", "-p", "9"])]:
        test(f"IPv6 {label} ::1", ["-6"] + mode + base + ["::1"], required=info,
             must=[r"^\s*1\s+::1\s+[\d.]+ ms"])

    # Real network (may be filtered on CI runners)
    real = ["-n", "-m", "4", "-q", "2", "-w", "2", "8.8.8.8"]
    for label, mode in [("ICMP", ["-I"]), ("UDP", []), ("TCP", ["-T", "-p", "443"])]:
        test(f"real path {label} (8.8.8.8)", mode + real, required=info,
             must=[r"^\s*1\s+\d+\.\d+\.\d+\.\d+\s+[\d.]+ ms"])
    test("real path names", ["-m", "2", "-q", "1", "-w", "2", "8.8.8.8"], required=info,
         must=[r"\(\d+\.\d+\.\d+\.\d+\)"])

    # Unprivileged run must fail with a helpful message
    if hasattr(os, "setuid") and os.geteuid() == 0:
        try:
            import pwd
            pw = pwd.getpwnam("nobody")
            uid, gid = pw.pw_uid, pw.pw_gid
            test("non-root gives helpful error", base + [LO], required=info, rc=1,
                 must=[r"raw sockets need elevated rights"], user=(uid, gid))
        except Exception as e:                       # no 'nobody' user etc.
            skip("non-root gives helpful error", str(e))
    else:
        skip("non-root gives helpful error", "not running as root")

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

    return 1 if f_req else 0


if __name__ == "__main__":
    sys.exit(main())
