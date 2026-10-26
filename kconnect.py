#!/usr/bin/env python3
import ctypes
import socket
import struct
import functools
import collections
import argparse
from bcc import BPF
from rich.console import Console
from rich.table   import Table
from rich.live    import Live
from rich.text    import Text
from rich.panel   import Panel
from rich.console import Group

ap = argparse.ArgumentParser(
    description="KConnect — live TCP/UDP process monitor with bandwidth tracking",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
examples:
  sudo python3 kconnect.py
  sudo python3 kconnect.py --comm chrome
  sudo python3 kconnect.py --threshold 5242880  # flag processes exceeding 5MB
    """
)
ap.add_argument("--pid",       type=int,            help="trace only this PID")
ap.add_argument("--comm",      type=str,            help="trace only this process name (substring match)")
ap.add_argument("--port",      type=int,            help="trace only this destination port")
ap.add_argument("--no-dns",    action="store_true", help="skip hostname resolution (faster)")
ap.add_argument("--no-udp",    action="store_true", help="trace TCP only, skip UDP hooks")
ap.add_argument("--threshold", type=int, default=1048576, help="bandwidth threshold in bytes to flag processes (default: 1MB)")
args = ap.parse_args()

print("Loading eBPF program... ", end="", flush=True)

b = BPF(src_file="kconnect.bpf.c")
print("ok")

b.attach_kprobe(event="tcp_connect",      fn_name="trace_tcp4")
b.attach_kprobe(event="tcp_v6_connect",   fn_name="trace_tcp6")
b.attach_kprobe(event="tcp_sendmsg",      fn_name="trace_tcp_sendmsg")
b.attach_kprobe(event="tcp_cleanup_rbuf", fn_name="trace_tcp_cleanup_rbuf")

if not args.no_udp:
    b.attach_kprobe(event="udp_sendmsg",   fn_name="trace_udp4")
    b.attach_kprobe(event="udpv6_sendmsg", fn_name="trace_udp6")

class Event(ctypes.Structure):
    _fields_ = [
        ("pid",     ctypes.c_uint32),
        ("uid",     ctypes.c_uint32),
        ("comm",    ctypes.c_char * 16),
        ("saddr",   ctypes.c_uint32),
        ("daddr",   ctypes.c_uint32),
        ("saddr6",  ctypes.c_uint8 * 16),
        ("daddr6",  ctypes.c_uint8 * 16),
        ("sport",   ctypes.c_uint16),
        ("dport",   ctypes.c_uint16),
        ("proto",   ctypes.c_uint8),
        ("is_ipv6", ctypes.c_uint8),
    ]

class TrafficVal(ctypes.Structure):
    _fields_ = [
        ("sent_bytes", ctypes.c_uint64),
        ("recv_bytes", ctypes.c_uint64),
        ("comm",       ctypes.c_char * 16),
    ]

def fmt_ip(e: Event):
    if e.is_ipv6:
        src = socket.inet_ntop(socket.AF_INET6, bytes(e.saddr6))
        dst = socket.inet_ntop(socket.AF_INET6, bytes(e.daddr6))
    else:
        src = socket.inet_ntoa(struct.pack("I", e.saddr))
        dst = socket.inet_ntoa(struct.pack("I", e.daddr))
    return src, dst

def fmt_bytes(b_val):
    if b_val < 1024:
        return f"{b_val} B"
    elif b_val < 1024 * 1024:
        return f"{b_val / 1024:.1f} KB"
    elif b_val < 1024 * 1024 * 1024:
        return f"{b_val / (1024 * 1024):.1f} MB"
    else:
        return f"{b_val / (1024 * 1024 * 1024):.2f} GB"

@functools.lru_cache(maxsize=1024)
def resolve(ip: str) -> str:
    if args.no_dns:
        return ""
    try:
        host = socket.gethostbyaddr(ip)[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) > 2 else host
    except Exception:
        return ""

log        = collections.deque(maxlen=30)
proc_count = collections.defaultdict(int)
console    = Console()

def on_event(cpu, data, size):
    e = ctypes.cast(data, ctypes.POINTER(Event)).contents
    name = e.comm.decode("utf-8", errors="replace").rstrip("\x00")

    if args.pid  and e.pid   != args.pid:    return
    if args.comm and args.comm not in name:  return
    if args.port and e.dport != args.port:   return

    _, dst = fmt_ip(e)
    proto  = "TCP" if e.proto == 6 else "UDP"
    host   = resolve(dst)

    proc_count[name] += 1
    log.append((e.pid, name, proto, dst, e.dport, host))

b["events"].open_perf_buffer(on_event, page_cnt=64)

def get_traffic_data():
    traffic_map = b["traffic_map"]
    data = {}
    for k, v in traffic_map.items():
        pid = k.value
        name = v.comm.decode("utf-8", errors="replace").rstrip("\x00")
        if not name:
            name = f"pid_{pid}"
        
        if args.pid and pid != args.pid:
            continue
        if args.comm and args.comm not in name:
            continue

        sent = v.sent_bytes
        recv = v.recv_bytes
        total = sent + recv
        if name not in data:
            data[name] = {"sent": 0, "recv": 0, "total": 0, "pids": set()}
        data[name]["sent"] += sent
        data[name]["recv"] += recv
        data[name]["total"] += total
        data[name]["pids"].add(pid)
    return data

def build_table() -> Table:
    t = Table(show_header=True, header_style="bold", expand=True, show_lines=False, box=None)
    t.add_column("PID",     style="dim",        width=8)
    t.add_column("Process", style="bold white", width=16)
    t.add_column("Proto",                       width=6)
    t.add_column("Dest IP",                     width=20)
    t.add_column("Port",                        width=7)
    t.add_column("Host",    style="dim",        ratio=1)

    for pid, name, proto, dst, port, host in reversed(log):
        proto_text = Text(proto, style="cyan" if proto == "TCP" else "magenta")
        port_text  = Text(str(port), style="red" if port < 1024 else "green")
        t.add_row(str(pid), name, proto_text, dst, port_text, host or "")
    return t

def build_bandwidth_panel() -> Panel:
    traffic = get_traffic_data()
    sorted_traffic = sorted(traffic.items(), key=lambda x: -x[1]["total"])[:6]
    
    t = Table(show_header=True, header_style="bold cyan", expand=True, box=None, padding=(0, 2))
    t.add_column("Process", style="bold white", width=16)
    t.add_column("Sent", justify="right", width=12)
    t.add_column("Received", justify="right", width=12)
    t.add_column("Total BW", justify="right", width=12)
    t.add_column("Status / Flag", width=20)

    if not sorted_traffic:
        return Panel("[dim]waiting for bandwidth data...[/dim]", title="[bold]bandwidth usage & flags[/bold]", border_style="dim")

    has_flagged = False
    for name, stats in sorted_traffic:
        total = stats["total"]
        is_flagged = total > args.threshold
        if is_flagged:
            has_flagged = True
            status = Text("⚠️ HIGH BANDWIDTH", style="bold red")
        else:
            status = Text("Normal", style="green")
        
        t.add_row(
            name,
            fmt_bytes(stats["sent"]),
            fmt_bytes(stats["recv"]),
            fmt_bytes(total),
            status
        )

    border_color = "yellow" if has_flagged else "dim"
    return Panel(t, title="[bold]bandwidth usage & high-usage flags[/bold]", border_style=border_color)

def build_display():
    return Group(build_table(), build_bandwidth_panel())

try:
    with Live(build_display(), refresh_per_second=4, screen=False) as live:
        while True:
            b.perf_buffer_poll(timeout=100)
            live.update(build_display())
except KeyboardInterrupt:
    pass

total = sum(proc_count.values())
console.print(f"\n[bold]KConnect stopped.[/bold] Captured {total} connections.\n")
console.print("[bold]Final bandwidth summary:[/bold]")
traffic = get_traffic_data()
for name, stats in sorted(traffic.items(), key=lambda x: -x[1]["total"])[:10]:
    flag = " [bold red]⚠️ FLAGGED (Excessive Bandwidth)[/bold red]" if stats["total"] > args.threshold else ""
    console.print(f"  [cyan]{name:<20}[/cyan] Sent: {fmt_bytes(stats['sent'])}, Recv: {fmt_bytes(stats['recv'])}, Total: {fmt_bytes(stats['total'])}{flag}")
