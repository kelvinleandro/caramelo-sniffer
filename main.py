import curses
import math
import threading

import pandas as pd

from capture import *
from utils import *

# key options
OPTIONS = {
    "Q": "QUIT",
    "S": "START/STOP CAPTURE",
    "F": "FILTER",
    u" \u2191 | \u2193 ": "Row up/down",
    u" \u2190 | \u2192 ": "Previous/next page",
}

# transport protocols
PROTOCOLS_OPTIONS = ["ALL", "TCP", "UDP", "ICMP"]


def display_options(stdscr) -> None:
    # stdscr.clear()
    h, w = stdscr.getmaxyx()  # screen dimension
    menu_str = ""
    for key, value in OPTIONS.items():
        menu_str += f"{key} {value}  "

    # Calculating starting x to center the menu
    x = w // 2 - len(menu_str) // 2
    y = h // 2

    for key, value in OPTIONS.items():
        stdscr.addstr(y, x, key, curses.A_STANDOUT | curses.A_BOLD)
        x += len(key)
        stdscr.addstr(y, x, " " + value + "  ", curses.A_BOLD)
        x += len(value) + 3  # Plus 3 for the spaces (1 between key-value, 2 between items)

    stdscr.refresh()


def display_status(stdscr, proto: int, capture_state: str, n_packets: int) -> None:
    protocol_name = PROTOCOLS_OPTIONS[proto]
    match protocol_name:
        case "TCP":
            proto_color = 3
        case "UDP":
            proto_color = 4
        case "ICMP":
            proto_color = 5
        case _:
            proto_color = 0

    # Display updated information
    capture_text = f"{capture_state:<3}"
    protocol_text = f"Transport Protocol: "
    counter_text = f"Packets captured: {n_packets}"

    # Display the capture state with dynamic color
    stdscr.addstr(1, 2, "Capture: ")
    stdscr.addstr(1, 11, capture_text, curses.color_pair(1 if capture_state == "OFF" else 2))

    # Display the protocol text in default color and the protocol name in its specific color
    stdscr.addstr(1, 17, protocol_text)
    stdscr.addstr(1, 17 + len(protocol_text), f"{protocol_name:<4}", curses.color_pair(proto_color))

    # Display the packet counter
    stdscr.addstr(1, 17 + len(protocol_text) + len(protocol_name), "\t" + counter_text)

    # Refresh the screen to update the display
    stdscr.refresh()


def display_table(stdscr, df: pd.DataFrame) -> None:
    # TODO: show table
    h, w = stdscr.getmaxyx()  # screen dimension
    max_cols = w - 2  # excluding borders
    max_lines = h - 3  # excluding borders and table header
    cols_dim = {
        "Number": math.floor(max_cols * 0.1) - 1,
        "Time": math.floor(max_cols * 0.1) - 1,
        "MAC address src": math.floor(max_cols * 0.3) - 1,
        "MAC address dst": math.floor(max_cols * 0.3) - 1,
        "Protocol": math.floor(max_cols * 0.1) - 1,
        "Length": math.floor(max_cols * 0.1),
    }
    table_header = "|".join(center_string(col, length) for col, length in cols_dim.items())

    stdscr.addstr(1, 1, table_header, curses.A_BOLD | curses.A_REVERSE)
    stdscr.addstr(h - 2, 3, f"h: {h} ")
    stdscr.addstr(h - 2, 10, f"w: {w}")
    stdscr.refresh()


def display_more_info(stdscr) -> None:
    # Show other info in mid-right screen
    # TODO: Page 1/3: Internet Protocol
    # TODO: Page 2/3: Transport Protocol
    # TODO: Page 3/3: show "non-converted" bytes (scrolling up automatically)
    pass


def main(stdscr) -> None:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sock.setblocking(False)
    counter = [0]
    enable = ["OFF"]
    transport_filter = 0
    df = pd.DataFrame(
        columns=["number", "time", "t_captured", "mac_src", "mac_dst", "protocol", "length", "rest"]
    )

    stdscr.refresh()
    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(True)  # making getch() non-blocking
    MAX_HEIGHT, MAX_WIDTH = stdscr.getmaxyx()  # Screen max width and height

    # Defining colors
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK)  # for TCP
    curses.init_pair(4, curses.COLOR_MAGENTA, curses.COLOR_BLACK)  # for UDP
    curses.init_pair(5, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # for ICMP

    # Create top window
    win_top = curses.newwin(int(MAX_HEIGHT * 0.10), MAX_WIDTH, 0, 0)

    # Create middle-left window
    win_mid_l = curses.newwin(int(MAX_HEIGHT * 0.80), int(MAX_WIDTH * 0.70), int(MAX_HEIGHT * 0.10), 0)

    # Create middle-right window
    win_mid_r = curses.newwin(int(MAX_HEIGHT * 0.80), int(MAX_WIDTH * 0.30), int(MAX_HEIGHT * 0.10),
                              int(MAX_WIDTH * 0.70))

    # Create bottom window
    win_bottom = curses.newwin(int(MAX_HEIGHT * 0.10), MAX_WIDTH, int(MAX_HEIGHT * 0.90), 0)

    # Set box and refresh each window to draw them on the screen
    for win in [win_top, win_mid_l, win_mid_r, win_bottom]:
        win.box()
        win.refresh()

    while True:
        # stdscr.clear()
        display_options(win_bottom)
        display_status(win_top, transport_filter, enable[0], len(df))

        display_table(win_mid_l, df)

        try:
            key = stdscr.getch()
        except:
            key = None

        if key == ord('q'):
            break
        elif key == ord('s'):
            if enable[0] == "ON":
                enable[0] = "OFF"
            else:
                enable[0] = "ON"
                threading.Thread(target=start_packet_capture, args=(enable, sock, df)).start()
        elif key == ord('f'):
            # Cycle through the elements
            transport_filter = (transport_filter + 1) % len(PROTOCOLS_OPTIONS)

        stdscr.refresh()


if __name__ == "__main__":
    curses.wrapper(main)
