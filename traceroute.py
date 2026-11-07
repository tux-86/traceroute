#!/usr/bin/env python3
"""
traceroute.py - Linux-style traceroute for Windows 11 (also runs on Linux/macOS).

Modes:    UDP (default), ICMP echo (-I), TCP SYN (-T); IPv4 and IPv6
Platforms: Windows, Linux, macOS, FreeBSD (macOS/BSD: run with sudo; -i works on
          Linux, Windows and macOS only, -l on Linux only).
Needs:    Python 3.9+. Raw-socket modes (UDP, TCP, and ICMP on Linux) need an elevated
          terminal ("Run as administrator" on Windows, root/sudo on Linux).
          On Windows, ICMP mode (-I) uses the Windows ICMP API like tracert does,
          so it works without admin rights and sees every hop (--raw disables this).

Examples:
    python traceroute.py google.com
    python traceroute.py -I -n 8.8.8.8
    python traceroute.py -T -p 443 example.com
    python traceroute.py -6 -I ipv6.google.com
    python traceroute.py -A -e example.com
    python traceroute.py --mtu example.com
    python traceroute.py -m 20 -q 1 -w 1.5 example.com 80
"""
import argparse
import ctypes
import errno
import ipaddress
import os
import select
import socket
import struct
import sys
import time
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

VERSION = "traceroute.py 2.0 (Linux-compatible, Python)"
IS_WIN = os.name == "nt"

ICMP_ECHO = 8
PLATEAUS = [65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68]

# Flags printed after the RTT, as the Linux traceroute does
UNREACH4 = {0: "!N", 1: "!H", 2: "!P", 5: "!S", 13: "!X", 14: "!V", 15: "!C"}
UNREACH6 = {0: "!N", 1: "!X", 2: "!S", 3: "!H"}

Reply = namedtuple("Reply", "src kind code key mtu ext")
_warned = set()


def warn(msg: str) -> None:
    if msg not in _warned:
        _warned.add(msg)
        print(f"traceroute: warning: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Platform-specific socket options (numbers differ between Linux, macOS, BSD, Windows)
# --------------------------------------------------------------------------- #
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
IS_FREEBSD = sys.platform.startswith("freebsd")


def set_dont_fragment(sock: socket.socket, v6: bool) -> None:
    """Set the Don't Fragment bit. Raises NotImplementedError where there is no way to."""
    if v6:
        opt = getattr(socket, "IPV6_DONTFRAG", 14 if IS_WIN else 62)
        sock.setsockopt(socket.IPPROTO_IPV6, opt, 1)
    elif IS_WIN:
        sock.setsockopt(socket.IPPROTO_IP, 14, 1)        # IP_DONTFRAGMENT
    elif IS_LINUX:
        sock.setsockopt(socket.IPPROTO_IP, 10, 2)        # IP_MTU_DISCOVER = IP_PMTUDISC_DO
    elif IS_MAC:
        sock.setsockopt(socket.IPPROTO_IP, 28, 1)        # IP_DONTFRAG
    elif IS_FREEBSD:
        sock.setsockopt(socket.IPPROTO_IP, 67, 1)        # IP_DONTFRAG
    else:
        raise NotImplementedError("IPv4 Don't Fragment is not supported on this platform")


def bind_to_interface(sock: socket.socket, name: str, index, v6: bool) -> None:
    """Send through a given interface (-i). Raises NotImplementedError where unsupported."""
    if IS_WIN:
        if v6:
            sock.setsockopt(socket.IPPROTO_IPV6, 31, index)                 # IPV6_UNICAST_IF
        else:
            sock.setsockopt(socket.IPPROTO_IP, 31, struct.pack("!I", index))  # IP_UNICAST_IF
    elif IS_LINUX:
        sock.setsockopt(socket.SOL_SOCKET, 25, name.encode())               # SO_BINDTODEVICE
    elif IS_MAC:
        if index is None:
            raise OSError(errno.ENODEV, "No such device")
        if v6:
            sock.setsockopt(socket.IPPROTO_IPV6, 125, index)                # IPV6_BOUND_IF
        else:
            sock.setsockopt(socket.IPPROTO_IP, 25, index)                   # IP_BOUND_IF
    else:
        raise NotImplementedError("-i is not supported on this platform; use -s <source address>")


# --------------------------------------------------------------------------- #
# Packet helpers
# --------------------------------------------------------------------------- #
def norm(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.split("%")[0]))
    except ValueError:
        return ip


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def parse_extensions(icmp: bytes, v6: bool):
    """RFC 4884 ICMP extensions; returns printable MPLS label stack entries."""
    if len(icmp) < 8:
        return []
    words = icmp[4] if v6 else icmp[5]
    if words == 0:
        return []
    off = 8 + words * (8 if v6 else 4)
    ext = icmp[off:]
    if len(ext) < 8 or (ext[0] >> 4) != 2:
        return []
    out, pos = [], 4
    while pos + 4 <= len(ext):
        olen, cls, ctype = struct.unpack("!HBB", ext[pos:pos + 4])
        if olen < 4 or pos + olen > len(ext):
            break
        body = ext[pos + 4:pos + olen]
        if cls == 1 and ctype == 1:                      # MPLS label stack
            for i in range(0, len(body) - 3, 4):
                w = struct.unpack("!I", body[i:i + 4])[0]
                out.append(f"<MPLS:L={w >> 12},E={(w >> 9) & 7},S={(w >> 8) & 1},T={w & 0xFF}>")
        pos += olen
    return out


def parse_icmp4(data: bytes):
    if len(data) < 28 or (data[0] >> 4) != 4 or data[9] != 1:   # IPv4 + ICMP only
        return None
    ihl = (data[0] & 0x0F) * 4
    if len(data) < ihl + 8:
        return None
    src = socket.inet_ntoa(data[12:16])
    icmp = data[ihl:]
    typ, code = icmp[0], icmp[1]

    if typ == 0:
        ident, seq = struct.unpack("!HH", icmp[4:8])
        return Reply(src, "echo_reply", code, ("icmp", ident, seq), 0, [])
    if typ not in (3, 11):
        return None

    inner = icmp[8:]
    if len(inner) < 28:
        return None
    iihl = (inner[0] & 0x0F) * 4
    proto = inner[9]
    l4 = inner[iihl:iihl + 8]
    if len(l4) < 8:
        return None
    if proto == 1:
        t, _c, _cs, ident, seq = struct.unpack("!BBHHH", l4)
        if t != ICMP_ECHO:
            return None
        key = ("icmp", ident, seq)
    elif proto in (6, 17):
        sport, dport = struct.unpack("!HH", l4[:4])
        key = ("tcp" if proto == 6 else "udp", sport, dport)
    else:
        return None

    if typ == 11:
        kind, mtu = "time_exceeded", 0
    elif code == 4:
        kind, mtu = "toobig", struct.unpack("!H", icmp[6:8])[0]
    else:
        kind, mtu = "unreach", 0
    return Reply(src, kind, code, key, mtu, parse_extensions(icmp, False))


def parse_icmp6(data: bytes, src: str):
    """data is the bare ICMPv6 message (raw IPv6 sockets give no IP header)."""
    if len(data) < 8:
        return None
    typ, code = data[0], data[1]
    if typ == 129:
        ident, seq = struct.unpack("!HH", data[4:8])
        return Reply(src, "echo_reply", code, ("icmp", ident, seq), 0, [])
    if typ not in (1, 2, 3):
        return None

    inner = data[8:]
    if len(inner) < 48:
        return None
    nxt = inner[6]
    l4 = inner[40:48]
    if nxt == 58:
        t, _c, _cs, ident, seq = struct.unpack("!BBHHH", l4)
        if t != 128:
            return None
        key = ("icmp", ident, seq)
    elif nxt in (6, 17):
        sport, dport = struct.unpack("!HH", l4[:4])
        key = ("tcp" if nxt == 6 else "udp", sport, dport)
    else:
        return None

    kind = {1: "unreach", 2: "toobig", 3: "time_exceeded"}[typ]
    mtu = struct.unpack("!I", data[4:8])[0] if typ == 2 else 0
    return Reply(src, kind, code, key, mtu, parse_extensions(data, True))


def lsrr_option(gateways, final):
    """IPv4 loose source route option (the kernel treats the first entry as next hop)."""
    data = b"".join(socket.inet_aton(x) for x in list(gateways) + [final])
    opt = bytes([0x83, 3 + len(data), 4]) + data
    return opt + b"\x01" * ((-len(opt)) % 4)


def reverse_lookup(ip: str, debug: bool = False):
    """Reverse DNS.

    Windows: a plain DNS PTR query via nslookup first. Windows' own getnameinfo and
    gethostbyaddr fall back to slow NetBIOS queries when no PTR record exists, which
    stalls the trace. The slow resolver is only tried for private addresses, where
    local names (hosts file, mDNS, NetBIOS) are plausible.
    Elsewhere: getnameinfo, then gethostbyaddr.
    """
    tried = []

    def system_resolver():
        try:
            name = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
            if name and norm(name) != norm(ip):
                return name
            tried.append("getnameinfo: no name")
        except (OSError, UnicodeError) as e:
            tried.append(f"getnameinfo: {e}")
        try:
            name = socket.gethostbyaddr(ip)[0]
            if name and norm(name) != norm(ip):
                return name
            tried.append("gethostbyaddr: no name")
        except (OSError, UnicodeError) as e:
            tried.append(f"gethostbyaddr: {e}")
        return None

    name = None
    if IS_WIN:
        try:
            name = nslookup_ptr(ip)
            if not name:
                tried.append("nslookup: no name")
        except Exception as e:
            tried.append(f"nslookup: {e}")
            name = system_resolver()            # nslookup unusable: fall back to the OS
        else:
            if not name:
                try:
                    private = not ipaddress.ip_address(ip.split("%")[0]).is_global
                except ValueError:
                    private = False
                if private:
                    name = system_resolver()
    else:
        name = system_resolver()

    if not name and debug:
        print(f"[debug] no reverse DNS name for {ip}: {'; '.join(tried)}", file=sys.stderr)
    return name


def parse_nslookup_ptr(text: str):
    """Pull the host name out of `nslookup -type=PTR <x.in-addr.arpa>` output (any locale)."""
    for line in text.splitlines():
        low = line.lower()
        if ".arpa" in low and "=" in line:
            name = line.split("=", 1)[1].strip().rstrip(".")
            if name and " " not in name:
                return name
    return None


def nslookup_ptr(ip: str):
    import subprocess
    arpa = ipaddress.ip_address(ip.split("%")[0]).reverse_pointer
    flags = subprocess.CREATE_NO_WINDOW if IS_WIN else 0
    out = subprocess.run(["nslookup", "-type=PTR", arpa], capture_output=True,
                         timeout=4, creationflags=flags)
    return parse_nslookup_ptr(out.stdout.decode("utf-8", "replace") +
                              out.stderr.decode("utf-8", "replace"))


# --------------------------------------------------------------------------- #
# AS lookups (-A) via Team Cymru whois
# --------------------------------------------------------------------------- #
def parse_cymru(text: str):
    out = {}
    for line in text.splitlines():
        parts = [x.strip() for x in line.split("|")]
        if len(parts) >= 2 and parts[0] and parts[0].split()[0].isdigit():
            out[norm(parts[1])] = "AS" + parts[0].split()[0]
    return out


def as_lookup(addrs):
    res = {x: "*" for x in addrs}
    targets = []
    for x in addrs:
        try:
            if ipaddress.ip_address(x).is_global:
                targets.append(x)
        except ValueError:
            pass
    if not targets:
        return res
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=5) as s:
            s.sendall(("begin\nnoheader\n" + "\n".join(targets) + "\nend\n").encode())
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        for ip, asn in parse_cymru(buf.decode("utf-8", "replace")).items():
            if ip in res:
                res[ip] = asn
    except OSError:
        pass
    return res


# --------------------------------------------------------------------------- #
# Windows ICMP API (iphlpapi) - what tracert uses; needs no raw sockets / admin
# --------------------------------------------------------------------------- #
class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.c_void_p)]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_uint32),
                ("RoundTripTime", ctypes.c_uint32), ("DataSize", ctypes.c_ushort),
                ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                ("Options", IP_OPTION_INFORMATION)]


IP_SUCCESS = 0
IP_PACKET_TOO_BIG = 11009
IP_TTL_EXPIRED_TRANSIT = 11013
IP_TTL_EXPIRED_REASSEM = 11014
API_UNREACH = {11002: "!N", 11003: "!H", 11004: "!P", 11005: "!<3>"}


class Probe:
    def __init__(self, ttl, key, sock=None):
        self.ttl = ttl
        self.key = key
        self.fut = None           # Windows ICMP API: future with the result
        self.sock = sock          # per-probe TCP socket
        self.sent = time.perf_counter()
        self.deadline = 0.0
        self.addr = None
        self.rtt = None
        self.flag = ""
        self.pre = ""             # extra flag such as F=1492
        self.ext = []
        self.new_mtu = None       # set when a router asked for a smaller packet (--mtu)
        self.reached = False
        self.stop = False


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(
        prog="traceroute", add_help=False,
        description="Print the route packets take to a network host.")
    p.add_argument("--help", action="help", help="show this help and exit")
    p.add_argument("-V", "--version", action="store_true", help="print version and exit")
    p.add_argument("host", nargs="?", help="destination host name or IP address")
    p.add_argument("packetlen", nargs="?", type=int, default=None,
                   help="total packet size in bytes (default 60, IPv6 80)")
    p.add_argument("-f", "--first", dest="first", type=int, default=1, metavar="first_ttl",
                   help="start from this TTL / hop limit (default 1)")
    p.add_argument("-m", "--max-hops", dest="max_hops", type=int, default=30, metavar="max_ttl",
                   help="maximum number of hops (default 30)")
    p.add_argument("-q", "--queries", type=int, default=3, metavar="nqueries",
                   help="probes per hop (default 3)")
    p.add_argument("-N", "--sim-queries", dest="sim", type=int, default=None, metavar="squeries",
                   help="number of probes sent at the same time (default: all probes of a hop)")
    p.add_argument("-w", "--wait", type=float, default=3.0, metavar="secs",
                   help="seconds to wait for a reply (default 3)")
    p.add_argument("-z", "--sendwait", type=float, default=0.0, metavar="sendwait",
                   help="pause between probes; >10 means milliseconds, else seconds")
    p.add_argument("-p", "--port", type=int, metavar="port",
                   help="UDP: base destination port (default 33434); TCP: port (default 80)")
    p.add_argument("-s", "--source", metavar="src_addr", help="source address to use")
    p.add_argument("-i", "--interface", metavar="device",
                   help="network interface (Linux: name; Windows: name or index; "
                        "an IP address works like -s)")
    p.add_argument("-g", "--gateway", action="append", metavar="gate",
                   help="IPv4 loose source route gateway (repeatable or comma separated, max 8)")
    p.add_argument("-t", "--tos", type=int, metavar="tos",
                   help="IPv4 TOS / IPv6 traffic class (0-255)")
    p.add_argument("-l", "--flowlabel", type=int, metavar="flow_label",
                   help="IPv6 flow label (Linux only)")
    p.add_argument("-n", action="store_true", dest="numeric",
                   help="do not resolve addresses to host names")
    p.add_argument("-A", "--as-path-lookups", action="store_true", dest="as_lookup",
                   help="look up AS numbers (Team Cymru whois)")
    p.add_argument("-e", "--extensions", action="store_true", dest="ext",
                   help="show ICMP extensions (RFC 4884, MPLS labels)")
    p.add_argument("--mtu", action="store_true",
                   help="discover path MTU (implies -F and -N 1)")
    p.add_argument("-M", "--module", dest="method", metavar="name",
                   choices=["default", "udp", "icmp", "tcp"],
                   help="probe method: default, udp, icmp or tcp")
    p.add_argument("-I", "--icmp", action="store_true", help="use ICMP ECHO probes")
    p.add_argument("-T", "--tcp", action="store_true", help="use TCP SYN probes")
    p.add_argument("-U", "--udp", action="store_true", help="use UDP probes (default)")
    p.add_argument("-F", "--dont-fragment", action="store_true", dest="df",
                   help="set the Don't Fragment bit")
    p.add_argument("--raw", action="store_true",
                   help="Windows: use raw sockets for ICMP mode instead of the Windows ICMP API")
    p.add_argument("--rcvall", type=int, choices=[0, 1, 3], default=None,
                   help="Windows raw sockets: SIO_RCVALL level (0=off, 1=RCVALL_ON, "
                        "3=IP level); default tries 3 then 1")
    p.add_argument("--debug", action="store_true",
                   help="print every ICMP message received (diagnostics)")
    p.add_argument("-4", action="store_true", dest="v4", help="use IPv4")
    p.add_argument("-6", action="store_true", dest="v6", help="use IPv6")
    return p.parse_args()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    a = parse_args()
    if a.version:
        print(VERSION)
        return 0
    if not a.host:
        sys.exit("Specify \"host\" missing argument.")

    if a.v4 and a.v6:
        sys.exit("traceroute: only one of -4, -6 may be given")
    if a.method:
        a.icmp, a.tcp, a.udp = a.method == "icmp", a.method == "tcp", a.method == "udp"
    if sum([a.icmp, a.tcp, a.udp]) > 1:
        sys.exit("traceroute: only one of -I, -T, -U may be given")
    if a.first < 1 or a.max_hops < a.first or a.queries < 1 or a.wait <= 0:
        sys.exit("traceroute: invalid option value")
    if a.tos is not None and not 0 <= a.tos <= 255:
        sys.exit("traceroute: tos must be 0-255")
    if a.flowlabel is not None and not 0 <= a.flowlabel <= 0xFFFFF:
        sys.exit("traceroute: flow label must be 0-1048575")
    if a.sim is not None and a.sim < 1:
        sys.exit("traceroute: invalid -N value")

    mode = "icmp" if a.icmp else "tcp" if a.tcp else "udp"
    port = a.port if a.port else (80 if mode == "tcp" else 33434)
    sendwait = (a.sendwait / 1000.0) if a.sendwait > 10 else a.sendwait

    # ---- resolve destination (IPv4 preferred when family is not forced) ----- #
    want = socket.AF_INET6 if a.v6 else socket.AF_INET if a.v4 else None
    family, dest_sa = None, None
    for fam in ([want] if want else [socket.AF_INET, socket.AF_INET6]):
        try:
            infos = socket.getaddrinfo(a.host, None, fam, socket.SOCK_DGRAM)
        except socket.gaierror:
            continue
        if infos:
            family, dest_sa = infos[0][0], infos[0][4]
            break
    if family is None:
        sys.exit(f"traceroute: unknown host {a.host}")

    v6 = family == socket.AF_INET6
    dest_ip = dest_sa[0].split("%")[0]
    dest_norm = norm(dest_ip)
    dest_scope = dest_sa[3] if v6 else 0
    HDR = 48 if v6 else 28

    gateways = []
    if a.gateway:
        if v6:
            sys.exit("traceroute: -g is only supported for IPv4")
        for item in a.gateway:
            for g in item.split(","):
                if g:
                    try:
                        gateways.append(socket.gethostbyname(g))
                    except OSError:
                        sys.exit(f"traceroute: unknown gateway {g}")
        if len(gateways) > 8:
            sys.exit("traceroute: at most 8 gateways are allowed")
    gw_opt = lsrr_option(gateways, dest_ip) if gateways else None
    if a.flowlabel is not None and not v6:
        sys.exit("traceroute: -l (flow label) requires IPv6")
    if a.flowlabel is not None and not IS_LINUX:
        warn("flow labels are only supported on Linux; -l ignored")

    if a.mtu:
        a.df = True
        a.sim = 1
    sim = a.sim if a.sim else a.queries
    if sendwait:
        sim = 1          # keep RTTs accurate: wait for each reply, then pause

    st = {"plen": max(a.packetlen if a.packetlen is not None else
                      (1500 if a.mtu else (80 if v6 else 60)), HDR),
          "flag": "",
          "flow": a.flowlabel if (a.flowlabel is not None and IS_LINUX) else 0}

    # ---- interface / source address --------------------------------------- #
    iface, iface_index, source = None, None, a.source
    if a.interface:
        try:
            ipaddress.ip_address(a.interface)
            source = source or a.interface
        except ValueError:
            iface = a.interface
            try:
                iface_index = (int(iface) if (IS_WIN and iface.isdigit())
                               else socket.if_nametoindex(iface))
            except (OSError, AttributeError):
                if IS_WIN:
                    sys.exit(f"traceroute: unknown interface {iface}")
                iface_index = None

    def sa(ip, prt):
        return (ip, prt, st["flow"], dest_scope) if v6 else (ip, prt)

    def apply_iface(sock):
        if not iface:
            return
        try:
            bind_to_interface(sock, iface, iface_index, v6)
        except NotImplementedError as e:
            sys.exit(f"traceroute: {e}")
        except OSError as e:
            sys.exit(f"traceroute: cannot use interface {iface}: {e.strerror or e}")

    def set_df(sock):
        try:
            set_dont_fragment(sock, v6)
        except (OSError, NotImplementedError) as e:
            warn(f"cannot set Don't Fragment: {e}")

    def configure(sock):
        if a.tos is not None:
            try:
                if v6:
                    sock.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_TCLASS", 39), a.tos)
                else:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, a.tos)
            except OSError as e:
                warn(f"cannot set TOS: {e}")
        if a.df:
            set_df(sock)
        apply_iface(sock)
        if gw_opt:
            try:
                sock.setsockopt(socket.IPPROTO_IP, 1, gw_opt)                   # IP_OPTIONS
            except OSError as e:
                warn(f"cannot set source route option: {e}")
        if st["flow"] and not v6:
            pass
        elif st["flow"]:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, 33, 1)                     # IPV6_FLOWINFO_SEND
            except OSError as e:
                warn(f"flow labels unavailable: {e}")
                st["flow"] = 0

    def set_ttl(sock, ttl):
        if v6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    try:
        t = socket.socket(family, socket.SOCK_DGRAM)
        apply_iface(t)
        t.connect(sa(dest_ip, 53) if not v6 else (dest_ip, 53, 0, dest_scope))
        sn = t.getsockname()
        if a.mtu:
            # Start from the MTU of the outgoing interface, as Linux traceroute does.
            # (IP_MTU exists on Linux and Windows only; macOS/BSD keep the 1500 default.)
            if IS_WIN or IS_LINUX:
                try:
                    opt = (72 if v6 else 73) if IS_WIN else (24 if v6 else 14)   # IP(V6)_MTU
                    local_mtu = t.getsockopt(socket.IPPROTO_IPV6 if v6 else socket.IPPROTO_IP, opt)
                    if a.packetlen is None and HDR + 8 <= local_mtu <= 65535:
                        st["plen"] = local_mtu
                except OSError:
                    pass                                # keep the 1500 default
            st["flag"] = f"F={st['plen']}"              # shown on the very first probe
        t.close()
    except OSError as e:
        sys.exit(f"traceroute: {e.strerror or e}")
    local_ip, local_scope = sn[0], (sn[3] if v6 else 0)
    if source:
        try:
            info = socket.getaddrinfo(source, None, family, socket.SOCK_DGRAM)[0][4]
            local_ip, local_scope = info[0], (info[3] if v6 else 0)
        except (socket.gaierror, IndexError):
            sys.exit(f"traceroute: cannot use source address {source}")

    def bind_sa(prt):
        return (local_ip, prt, 0, local_scope) if v6 else (local_ip, prt)

    # ---- Windows ICMP API (default for -I on Windows, like tracert) -------- #
    use_api = (IS_WIN and mode == "icmp" and not v6 and not a.raw and not a.ext
               and not gateways and not source and not iface)
    iph, api_pool, dest_addr = None, None, 0
    if use_api:
        iph = ctypes.WinDLL("iphlpapi", use_last_error=True)
        iph.IcmpCreateFile.restype = ctypes.c_void_p
        iph.IcmpCreateFile.argtypes = []
        iph.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        iph.IcmpSendEcho.restype = ctypes.c_uint32
        iph.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                     ctypes.c_ushort, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_uint32, ctypes.c_uint32]
        api_pool = ThreadPoolExecutor(max_workers=32)
        dest_addr = ctypes.c_uint32.from_buffer_copy(socket.inet_aton(dest_ip)).value

    def api_echo(ttl, size):
        """One blocking IcmpSendEcho call -> (status, address, rtt_ms)."""
        h = iph.IcmpCreateFile()
        if not h or h == ctypes.c_void_p(-1).value:
            return None, None, 0.0
        try:
            opts = IP_OPTION_INFORMATION(ttl, a.tos or 0, 2 if a.df else 0, 0, None)
            data = b"\x40" * size
            buf = ctypes.create_string_buffer(ctypes.sizeof(ICMP_ECHO_REPLY) + size + 256)
            t0 = time.perf_counter()
            n = iph.IcmpSendEcho(h, dest_addr, data or None, size, ctypes.byref(opts),
                                 buf, len(buf), int(a.wait * 1000))
            rtt = (time.perf_counter() - t0) * 1000.0
            if n == 0:
                return None, None, rtt
            rep = ICMP_ECHO_REPLY.from_buffer_copy(buf)
            addr = socket.inet_ntoa(struct.pack("=I", rep.Address))
            return rep.Status, addr, rtt
        finally:
            iph.IcmpCloseHandle(h)

    # ---- sockets ---------------------------------------------------------- #
    icmp = None
    if not use_api:
        try:
            icmp = socket.socket(family, socket.SOCK_RAW,
                                 socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
            configure(icmp)
            icmp.bind(bind_sa(0))
            if IS_WIN and not v6 and a.rcvall != 0:
                # Receive-all mode; level 3 = IP level (no promiscuous mode), 1 = RCVALL_ON.
                for level in ((3, 1) if a.rcvall is None else (a.rcvall,)):
                    try:
                        icmp.ioctl(socket.SIO_RCVALL, level)
                        if a.debug:
                            print(f"[debug] SIO_RCVALL level {level} enabled", file=sys.stderr)
                        break
                    except (OSError, AttributeError, ValueError) as e:
                        if a.debug:
                            print(f"[debug] SIO_RCVALL level {level} failed: {e}",
                                  file=sys.stderr)
                else:
                    warn("could not enable receive-all mode; intermediate hops may show '*'")
        except OSError as e:
            if isinstance(e, PermissionError) or getattr(e, "winerror", 0) == 10013:
                who = ("Run this from a terminal opened with 'Run as administrator'."
                       if IS_WIN else "Run it as root (e.g. with sudo).")
                sys.exit(f"traceroute: raw sockets need elevated rights. {who}")
            sys.exit(f"traceroute: cannot open raw socket: {e}")

    udp, udp_sport = None, 0
    if mode == "udp":
        udp = socket.socket(family, socket.SOCK_DGRAM)
        configure(udp)
        udp.bind(bind_sa(0))
        udp_sport = udp.getsockname()[1]

    ident = os.getpid() & 0xFFFF
    counter = 0
    name_cache, as_cache, name_futs = {}, {}, {}
    pool = ThreadPoolExecutor(max_workers=16)

    print(f"traceroute to {a.host} ({dest_ip}), {a.max_hops} hops max, "
          f"{st['plen']} byte packets", flush=True)

    # ----- probe sending ---------------------------------------------------- #
    def send_probe(ttl):
        nonlocal counter
        n = counter
        counter += 1
        payload = b"\x40" * max(st["plen"] - HDR, 0)

        if use_api:
            probe = Probe(ttl, ("api", n))
            probe.sent = time.perf_counter()
            probe.fut = api_pool.submit(api_echo, ttl, len(payload))
            return probe

        if mode == "icmp":
            seq = n & 0xFFFF
            typ = 128 if v6 else ICMP_ECHO
            hdr = struct.pack("!BBHHH", typ, 0, 0, ident, seq)
            cs = 0 if v6 else checksum(hdr + payload)   # ICMPv6: checksum filled by the stack
            pkt = struct.pack("!BBHHH", typ, 0, cs, ident, seq) + payload
            set_ttl(icmp, ttl)
            probe = Probe(ttl, ("icmp", ident, seq))
            probe.sent = time.perf_counter()
            icmp.sendto(pkt, sa(dest_ip, 0))
            return probe

        if mode == "udp":
            dport = port + n
            if dport > 65535:
                dport = 33434 + (n % 30000)
            set_ttl(udp, ttl)
            probe = Probe(ttl, ("udp", udp_sport, dport))
            probe.sent = time.perf_counter()
            try:
                udp.sendto(payload, sa(dest_ip, dport))
            except OSError as e:
                if e.errno in (errno.EMSGSIZE, errno.EINVAL):
                    raise
            return probe

        s = socket.socket(family, socket.SOCK_STREAM)
        configure(s)
        s.bind(bind_sa(0))
        sport = s.getsockname()[1]
        set_ttl(s, ttl)
        s.setblocking(False)
        probe = Probe(ttl, ("tcp", sport, port), sock=s)
        probe.sent = time.perf_counter()
        try:
            s.connect_ex(sa(dest_ip, port))
        except OSError:
            pass
        return probe

    def launch(ttl):
        """Send one probe, shrinking the packet if the local stack says it is too big."""
        while True:
            try:
                p = send_probe(ttl)
                break
            except OSError as e:
                if e.errno == errno.EINVAL and st["flow"]:
                    warn("flow label rejected by the kernel; -l ignored")
                    st["flow"] = 0
                    continue
                if e.errno == errno.EMSGSIZE and (a.mtu or a.df):
                    smaller = next((m for m in PLATEAUS if m < st["plen"]), None)
                    if smaller:
                        st["plen"] = smaller
                        st["flag"] = f"F={smaller}"
                        continue
                hint = (" (source routing is probably disabled by the operating system)"
                        if gateways and e.errno in (errno.EACCES, errno.EPERM) else "")
                sys.exit(f"traceroute: sendto: {e.strerror or e}{hint}")
        p.deadline = p.sent + a.wait
        if st["flag"]:
            p.pre, st["flag"] = st["flag"], ""
        return p

    # ----- reply collection ------------------------------------------------- #
    def rdns(ip):
        return reverse_lookup(ip, a.debug)

    def start_lookup(ip):
        """Begin the reverse DNS lookup as soon as a hop answers (like Linux does)."""
        if not a.numeric and ip not in name_futs:
            name_futs[ip] = pool.submit(rdns, ip)

    def finish(p, addr, now, flag="", reached=False, stop=False, ext=None):
        p.addr = norm(addr)
        start_lookup(p.addr)
        p.rtt = (now - p.sent) * 1000.0
        p.flag = flag
        p.reached = reached
        p.stop = stop
        p.ext = ext or []

    def collect_api(probes):
        for p in probes:
            try:
                status, addr, rtt = p.fut.result(timeout=a.wait + 5)
            except Exception:
                continue
            if status is None or addr is None:
                continue                                  # request timed out
            t = p.sent + rtt / 1000.0
            if status == IP_SUCCESS:
                finish(p, addr, t, reached=(norm(addr) == dest_norm))
            elif status in (IP_TTL_EXPIRED_TRANSIT, IP_TTL_EXPIRED_REASSEM):
                finish(p, addr, t)
            elif status == IP_PACKET_TOO_BIG:
                if a.mtu:
                    finish(p, addr, t)
                    p.new_mtu = 0                         # API gives no MTU: step down
                else:
                    finish(p, addr, t, flag="!F", stop=True)
            elif status in API_UNREACH:
                finish(p, addr, t, flag=API_UNREACH[status], stop=True)

    def collect(probes):
        if use_api:
            collect_api(probes)
        else:
            collect_raw(probes)

    def collect_raw(probes):
        pending = {p.key: p for p in probes}
        tcp_socks = {p.sock: p for p in probes if p.sock}
        unreach_tbl = UNREACH6 if v6 else UNREACH4

        while pending:
            now = time.perf_counter()
            for key in [k for k, p in pending.items() if now >= p.deadline]:
                del pending[key]
            if not pending:
                break
            timeout = max(0.0, min(p.deadline for p in pending.values()) - now)

            wl = [s for s, p in tcp_socks.items() if p.key in pending]
            r, w, x = select.select([icmp], wl, wl, timeout)
            now = time.perf_counter()

            if icmp in r:
                try:
                    data, frm = icmp.recvfrom(65535)
                except OSError:
                    data, frm = b"", None
                if v6:
                    res = parse_icmp6(data, norm(frm[0])) if frm else None
                else:
                    res = parse_icmp4(data)
                p = pending.get(res.key) if res else None
                if a.debug:
                    if res:
                        print(f"[debug] {res.kind} from {res.src} code={res.code} "
                              f"key={res.key} matched={p is not None}", file=sys.stderr)
                    elif not v6 and len(data) > 20 and data[9] == 1:
                        ihl = (data[0] & 0x0F) * 4
                        print(f"[debug] ignored ICMP type={data[ihl]} code={data[ihl + 1]} "
                              f"from {socket.inet_ntoa(data[12:16])}", file=sys.stderr)
                if p:
                    ext = res.ext if a.ext else []
                    if res.kind == "time_exceeded":
                        finish(p, res.src, now, ext=ext)
                    elif res.kind == "echo_reply":
                        finish(p, res.src, now, reached=(norm(res.src) == dest_norm), ext=ext)
                    elif res.kind == "toobig":
                        if a.mtu:
                            finish(p, res.src, now, ext=ext)
                            p.new_mtu = res.mtu
                        else:
                            f = f"!F-{res.mtu}" if res.mtu else "!F"
                            finish(p, res.src, now, flag=f, stop=True, ext=ext)
                    elif res.kind == "unreach":
                        port_unreach = (res.code == 4) if v6 else (res.code == 3)
                        if mode == "udp" and port_unreach:
                            finish(p, res.src, now, reached=True, ext=ext)
                        else:
                            finish(p, res.src, now,
                                   flag=unreach_tbl.get(res.code, f"!<{res.code}>"),
                                   stop=True, ext=ext)
                    del pending[res.key]

            for s in set(w) | set(x):
                p = tcp_socks.get(s)
                if not p or p.key not in pending:
                    continue
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0 and s in w:
                    finish(p, dest_ip, now, reached=True)      # SYN-ACK
                    del pending[p.key]
                elif err == errno.ECONNREFUSED:
                    finish(p, dest_ip, now, reached=True)      # RST
                    del pending[p.key]
                elif err != 0:
                    tcp_socks.pop(s, None)                     # other error: wait for ICMP

        for p in probes:
            if p.sock:
                try:
                    p.sock.close()
                except OSError:
                    pass

    def settle(ttl, p):
        """--mtu: when a router asks for a smaller packet, shrink and probe again."""
        for _ in range(12):
            if p.new_mtu is None:
                break
            m = p.new_mtu
            if HDR <= m < st["plen"]:
                st["plen"] = m
            else:
                smaller = next((x for x in PLATEAUS if x < st["plen"]), None)
                if smaller is None:
                    break
                st["plen"] = smaller
            carry = f"F={st['plen']}"
            p = launch(ttl)
            collect([p])
            if not p.pre:
                p.pre = carry
        return p

    # ----- name / AS resolution --------------------------------------------- #
    def resolve_names(addrs):
        deadline = time.monotonic() + 8.0
        for ip in addrs:
            start_lookup(ip)
            try:
                name_cache[ip] = name_futs[ip].result(timeout=max(0.0, deadline - time.monotonic()))
            except Exception:
                pass          # still running: show the plain address this time

    def label(ip):
        base = ip if a.numeric else f"{name_cache.get(ip) or ip} ({ip})"
        if a.as_lookup:
            base += f" [{as_cache.get(ip, '*')}]"
        return base

    # ----- main loop -------------------------------------------------------- #
    try:
        for ttl in range(a.first, a.max_hops + 1):
            probes, left = [], a.queries
            while left > 0:
                batch = []
                for i in range(min(sim, left)):
                    if (i or probes) and sendwait:
                        time.sleep(sendwait)
                    batch.append(launch(ttl))
                collect(batch)
                for p in batch:
                    probes.append(settle(ttl, p) if a.mtu else p)
                left -= len(batch)

            addrs = {p.addr for p in probes if p.addr}
            as_todo = [x for x in addrs if a.as_lookup and x not in as_cache]
            fut_as = pool.submit(as_lookup, as_todo) if as_todo else None
            if not a.numeric:
                resolve_names(addrs)
            if fut_as:
                try:
                    as_cache.update(fut_as.result(timeout=8))
                except Exception:
                    as_cache.update({x: "*" for x in as_todo})

            out = f"{ttl:2d}"
            last, first_piece = None, True
            for p in probes:
                if p.addr is None:
                    piece, sep = "*", " "
                else:
                    sep, piece = "  ", ""
                    if p.addr != last:
                        piece = label(p.addr) + "  "
                        last = p.addr
                    piece += f"{p.rtt:.3f} ms"
                    for tail in (*p.ext, p.flag, p.pre):
                        if tail:
                            piece += " " + tail
                out += ("  " if first_piece else sep) + piece
                first_piece = False
            print(out, flush=True)

            if any(p.reached or p.stop for p in probes):
                break
    except KeyboardInterrupt:
        print()
        return 130
    finally:
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            pool.shutdown(wait=False)
        if icmp:
            icmp.close()
        if udp:
            udp.close()
        if api_pool:
            api_pool.shutdown(wait=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
