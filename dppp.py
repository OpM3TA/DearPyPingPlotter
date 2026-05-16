#!/usr/bin/env python3
"""
ping_gui.py  —  Ping with a live Dear PyGui dashboard.
Windows: run as Administrator
Linux:   run as root / cap_net_raw

Usage: py ping_gui.py [host] [-c count] [-i interval] [-s size] [-t ttl] [-W timeout]
"""

import argparse
import os
import platform
import select
import socket
import struct
import threading
import time
from collections import deque

import dearpygui.dearpygui as dpg

IS_WINDOWS = platform.system() == "Windows"
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0
MAX_HISTORY       = 200
LOSS_WINDOW       = 20   # rolling window for loss %


# ── ICMP engine ──────────────────────────────────────────────────────────────

def checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) & 1:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def sshot(sender, app_data):
    dpg.output_frame_buffer("plot_screenshot.png")


def build_packet(seq: int, pid: int, payload_size: int) -> bytes:
    hdr = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, pid, seq)
    ts  = struct.pack("d", time.time())
    pad = bytes(max(0, payload_size - len(ts)))
    payload = ts + pad
    cs  = checksum(hdr + payload)
    hdr = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, cs, pid, seq)
    return hdr + payload


def parse_reply(data: bytes, pid: int, seq: int):
    ihl  = (data[0] & 0x0F) * 4
    ttl  = data[8]
    icmp = data[ihl:]
    if len(icmp) < 16:
        raise ValueError("too short")
    i_type, _, _, r_pid, r_seq = struct.unpack("!BBHHH", icmp[:8])
    if i_type != ICMP_ECHO_REPLY:
        raise ValueError(f"type={i_type}")
    if r_pid != pid:
        raise ValueError(f"pid {r_pid}!={pid}")
    if r_seq != seq:
        raise ValueError(f"seq {r_seq}!={seq}")
    send_time = struct.unpack("d", icmp[8:16])[0]
    return (time.time() - send_time) * 1000, ttl


def make_socket(dest_ip: str, ttl: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    if IS_WINDOWS:
        try:
            p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            p.connect((dest_ip, 80))
            local_ip = p.getsockname()[0]
            p.close()
        except Exception:
            local_ip = "0.0.0.0"
        sock.bind((local_ip, 0))
    else:
        sock.bind(("", 0))
    return sock


# ── Shared state ─────────────────────────────────────────────────────────────

class PingState:
    def __init__(self):
        self.lock      = threading.Lock()
        self.rtts      : deque[float] = deque(maxlen=MAX_HISTORY)
        self.xs        : deque[float] = deque(maxlen=MAX_HISTORY)
        # rolling window: True=received, False=lost — only appended after a
        # seq is fully resolved (reply received OR timeout confirmed)
        self.outcomes  : deque[bool]  = deque(maxlen=LOSS_WINDOW)
        self.sent      = 0
        self.recvd     = 0
        self.last_rtt  : float | None = None
        self.last_ttl  : int   | None = None
        self.log       : deque[str]   = deque(maxlen=120)
        self.running   = True
        self.dest      = ""
        self.host      = ""


state = PingState()


def ping_thread(host: str, count: int, interval: float,
                payload_size: int, ttl: int, timeout: float):
    try:
        dest = socket.gethostbyname(host)
    except socket.gaierror as e:
        with state.lock:
            state.log.append(f"[ERR] {host}: {e}")
        return

    with state.lock:
        state.dest = dest
        state.host = host

    pid = os.getpid() & 0xFFFF

    try:
        sock = make_socket(dest, ttl)
    except PermissionError:
        with state.lock:
            state.log.append("[ERR] Needs Administrator / root")
        return

    seq = 0
    try:
        while state.running:
            seq += 1
            pkt    = build_packet(seq, pid, payload_size)
            t_send = time.time()
            sock.sendto(pkt, (dest, 0))

            # NOTE: only increment sent here, NOT recvd — don't touch
            # outcomes until the seq is fully resolved below
            with state.lock:
                state.sent += 1

            deadline = t_send + timeout
            rtt = None

            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                if IS_WINDOWS:
                    sock.settimeout(remaining)
                    try:
                        data, addr = sock.recvfrom(1500)
                    except (socket.timeout, OSError):
                        break
                else:
                    if not select.select([sock], [], [], remaining)[0]:
                        break
                    data, addr = sock.recvfrom(1500)
                try:
                    rtt, recv_ttl = parse_reply(data, pid, seq)
                    with state.lock:
                        state.recvd   += 1
                        state.last_rtt = rtt
                        state.last_ttl = recv_ttl
                        state.rtts.append(rtt)
                        state.xs.append(seq)
                        state.outcomes.append(True)   # resolved: received
                        state.log.append(
                            f"[{seq:4d}]  {addr[0]}  ttl={recv_ttl}  {rtt:.2f} ms"
                        )
                    break
                except ValueError:
                    continue

            if rtt is None:
                with state.lock:
                    state.outcomes.append(False)      # resolved: lost
                    state.log.append(f"[{seq:4d}]  timeout")

            if count and seq >= count:
                break

            elapsed   = time.time() - t_send
            sleep_for = interval - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)

    finally:
        sock.close()
        with state.lock:
            state.running = False


# ── GUI ───────────────────────────────────────────────────────────────────────

def build_gui(host: str):
    dpg.create_context()
    dpg.create_viewport(title=f"ping  {host}", width=900, height=620,
                        resizable=True)
    dpg.setup_dearpygui()

    with dpg.theme() as global_theme:
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_color(dpg.mvThemeCol_WindowBg,       (10,  12,  18,  255))
            dpg.add_theme_color(dpg.mvThemeCol_ChildBg,        (14,  17,  24,  255))
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg,        (22,  27,  38,  255))
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive,  (20,  80,  160, 255))
            dpg.add_theme_color(dpg.mvThemeCol_Text,           (200, 220, 255, 255))
            dpg.add_theme_color(dpg.mvThemeCol_Border,         (40,  55,  80,  255))
            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding,  6)
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding,   4)
            dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing,     8, 6)
    dpg.bind_theme(global_theme)

    with dpg.theme() as series_theme:
        with dpg.theme_component(dpg.mvLineSeries):
            dpg.add_theme_color(dpg.mvPlotCol_Line, (0, 220, 255, 230),
                                category=dpg.mvThemeCat_Plots)
            dpg.add_theme_style(dpg.mvPlotStyleVar_LineWeight, 2,
                                category=dpg.mvThemeCat_Plots)

    with dpg.theme() as scatter_theme:
        with dpg.theme_component(dpg.mvScatterSeries):
            dpg.add_theme_color(dpg.mvPlotCol_MarkerFill,    (0, 255, 160, 200),
                                category=dpg.mvThemeCat_Plots)
            dpg.add_theme_color(dpg.mvPlotCol_MarkerOutline, (0, 255, 160, 200),
                                category=dpg.mvThemeCat_Plots)

    with dpg.window(label="", tag="main_win", no_title_bar=True,
                    no_move=True, no_resize=True, no_scrollbar=True):

        with dpg.group(horizontal=True):
            dpg.add_text("● PING", color=(0, 220, 255, 255))
            dpg.add_text(host.upper(), color=(255, 255, 255, 255))
            dpg.add_spacer(width=20)
            dpg.add_text("", tag="txt_dest", color=(140, 160, 200, 255))
        dpg.add_spacer(height=6)

        with dpg.group(horizontal=True):
            for tag, label in [
                ("card_rtt",  "LAST RTT"),
                ("card_avg",  "AVG"),
                ("card_min",  "MIN"),
                ("card_max",  "MAX"),
                ("card_loss", f"LOSS/{LOSS_WINDOW}"),
                ("card_ttl",  "TTL"),
            ]:
                with dpg.child_window(tag=f"cw_{tag}", width=130, height=68,
                                      border=True, no_scrollbar=True):
                    dpg.add_text(label, color=(90, 120, 170, 255))
                    dpg.add_text("—", tag=tag, color=(0, 220, 255, 255))

        dpg.add_spacer(height=8)

        with dpg.plot(label="Round-Trip Time  (ms)", tag="plot",
                      height=260, width=-1, anti_aliased=True):
            dpg.add_plot_legend()
            dpg.add_plot_axis(dpg.mvXAxis, label="seq", tag="x_axis")
            dpg.add_plot_axis(dpg.mvYAxis, label="ms",  tag="y_axis")
            dpg.set_axis_limits("y_axis", 0, 100)

            ls = dpg.add_line_series(   [], [], label="RTT",     parent="y_axis", tag="rtt_line")
            sc = dpg.add_scatter_series([], [], label="samples", parent="y_axis", tag="rtt_dots")
            dpg.bind_item_theme(ls, series_theme)
            dpg.bind_item_theme(sc, scatter_theme)

        dpg.add_spacer(height=8)
        dpg.add_button(label="Save Plot", callback=sshot)
        dpg.add_spacer(height=4)
        dpg.add_text("OUTPUT", color=(90, 120, 170, 255))
        dpg.add_input_text(tag="log_box", multiline=True, readonly=True,
                           width=-1, height=140, tab_input=False)

    def on_resize():
        w = dpg.get_viewport_client_width()
        h = dpg.get_viewport_client_height()
        dpg.set_item_width("main_win",  w)
        dpg.set_item_height("main_win", h)

    dpg.set_viewport_resize_callback(on_resize)
    dpg.show_viewport()
    on_resize()

    _prev_log_len = 0

    while dpg.is_dearpygui_running():
        with state.lock:
            rtts     = list(state.rtts)
            xs       = list(state.xs)
            outcomes = list(state.outcomes)
            last_rtt = state.last_rtt
            last_ttl = state.last_ttl
            dest     = state.dest
            log      = list(state.log)

        if last_rtt is not None:
            dpg.set_value("card_rtt", f"{last_rtt:.1f} ms")
        if last_ttl is not None:
            dpg.set_value("card_ttl", str(last_ttl))
        if rtts:
            dpg.set_value("card_avg", f"{sum(rtts)/len(rtts):.1f} ms")
            dpg.set_value("card_min", f"{min(rtts):.1f} ms")
            dpg.set_value("card_max", f"{max(rtts):.1f} ms")

        # loss: computed only from fully-resolved outcomes, rolling window
        if outcomes:
            loss  = 100 * outcomes.count(False) / len(outcomes)
            color = (255, 80, 80, 255) if loss > 5 else (0, 220, 255, 255)
            dpg.set_value("card_loss", f"{loss:.0f}%")
            dpg.configure_item("card_loss", color=color)

        dpg.set_value("txt_dest", f"({dest})" if dest else "")

        if xs:
            dpg.set_value("rtt_line", [xs, rtts])
            dpg.set_value("rtt_dots", [xs, rtts])
            hi = max(rtts) * 1.25 or 100
            dpg.set_axis_limits("y_axis", 0, hi)
            dpg.set_axis_limits("x_axis", max(0, xs[-1] - MAX_HISTORY), xs[-1] + 2)

        if len(log) != _prev_log_len:
            dpg.set_value("log_box", "\n".join(log))
            _prev_log_len = len(log)

        dpg.render_dearpygui_frame()

    dpg.destroy_context()


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="ping with Dear PyGui live plot")
    p.add_argument("host",  nargs="?", default="8.8.8.8")
    p.add_argument("-c",  dest="count",    type=int,   default=0,    metavar="N")
    p.add_argument("-i",  dest="interval", type=float, default=1.0,  metavar="SEC")
    p.add_argument("-s",  dest="size",     type=int,   default=56,   metavar="BYTES")
    p.add_argument("-t",  dest="ttl",      type=int,   default=128,  metavar="TTL")
    p.add_argument("-W",  dest="timeout",  type=float, default=2.0,  metavar="SEC")
    args = p.parse_args()

    t = threading.Thread(
        target=ping_thread,
        args=(args.host, args.count, args.interval,
              args.size, args.ttl, args.timeout),
        daemon=True,
    )
    t.start()

    build_gui(args.host)

    state.running = False
    t.join(timeout=3)


if __name__ == "__main__":
    main()
