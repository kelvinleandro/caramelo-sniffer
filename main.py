import curses
import math
import threading
import time
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


def display_table(stdscr, df: pd.DataFrame, current_row: int, display_start: int, transport_filter: int) -> None:
    # stdscr.clear()
    h, w = stdscr.getmaxyx()  # window dimensions
    max_cols = w - 2  # excluding borders
    n_rows = h - 3  # number of rows to display
    proto = PROTOCOLS_OPTIONS[transport_filter]

    # Apply filtering based on the protocol
    if proto != "ALL":
        df = df[df['protocol'] == proto]

    # Column dimensions based on the width of the screen
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

    for i in range(n_rows):
        if display_start + i < len(df):
            packet = df.iloc[display_start + i]
            line_str = generate_table_line(packet, cols_dim)
            color = select_line_color(packet)
            if i == current_row:
                stdscr.addstr(i + 2, 1, line_str, curses.color_pair(color) | curses.A_REVERSE)
            else:
                stdscr.addstr(i + 2, 1, line_str, curses.color_pair(color))

    stdscr.refresh()


def display_more_info(stdscr, df: pd.DataFrame, index: int, page: int) -> None:
    # TODO: Fix window clear and refresh when index or page changes
    h, w = stdscr.getmaxyx()  # window dimensions
    max_cols = w - 2  # excluding borders
    max_lines = h - 2
    packet = df.iloc[index]
    rest = packet["rest"]

    stdscr.addstr(1, 1, f"Page {page}/3", curses.A_BOLD)

    if page == 1:
        stdscr.addstr(2, 1, "Internet Protocol", curses.A_BOLD)
        if "ip_version" in rest:
            stdscr.addstr(4, 1, f"IP Version: {rest['ip_version']}")
            stdscr.addstr(5, 1, f"Header Length: {rest['ip_header_length']}")
            stdscr.addstr(6, 1, f"TTL: {rest['ip_ttl']}")
            stdscr.addstr(7, 1, f"IP Source: {rest['ip_src']}")
            stdscr.addstr(8, 1, f"IP Destination: {rest['ip_dst']}")
        else:
            stdscr.addstr(4, 1, "No information available for this protocol")
    elif page == 2:
        stdscr.addstr(2, 1, "Transport Protocol", curses.A_BOLD)
        if packet["protocol"] == "UDP":
            stdscr.addstr(4, 1, f"Port source: {rest['port_src']}")
            stdscr.addstr(5, 1, f"Port destination: {rest['port_dst']}")
            stdscr.addstr(6, 1, f"Length: {rest['length']}")
        elif packet["protocol"] == "TCP":
            stdscr.addstr(4, 1, f"Port source: {rest['port_src']}")
            stdscr.addstr(5, 1, f"Port destination: {rest['port_dst']}")
            stdscr.addstr(6, 1, f"Sequence number: {rest['sequence_number']}")
            stdscr.addstr(7, 1, f"Acknowledgment number: {rest['acknowledgment_number']}")
        elif packet["protocol"] == "ICMP":
            stdscr.addstr(4, 1, f"ICMP type: {rest['icmp_type']}")
            stdscr.addstr(5, 1, f"ICMP code: {rest['icmp_code']}")
            stdscr.addstr(6, 1, f"Checksum: {rest['checksum']}")
        else:
            stdscr.addstr(4, 1, "No information available for this protocol")
    elif page == 3:
        stdscr.addstr(2, 1, "Payload", curses.A_BOLD)
        display_scrolling_payload(stdscr, rest["payload"], max_cols, max_lines)

    stdscr.refresh()


def display_scrolling_payload(stdscr, payload: bytes, pad_width: int, max_height: int) -> None:
    text = ' '.join(r'\x{:02x}'.format(byte) for byte in payload)
    pad_height = math.ceil(len(text) / pad_width)
    pad = curses.newpad(pad_height, pad_width)
    pad.addstr(text, curses.color_pair(5))

    win_y, win_x = stdscr.getbegyx()

    # Define the relative offset within the window where the pad should start displaying
    start_y, start_x = 4, 1  # Pad's top-left corner relative to window

    # Window's upper left corner coordinates on screen (where to start showing in the window)
    sminrow = win_y + start_y
    smincol = win_x + start_x

    # Lower right corner coordinates on screen (limit to window size or specified max_height and pad_width)
    smaxrow = win_y + start_y + max_height - 1
    smaxcol = win_x + start_x + pad_width - 1

    if pad_height <= max_height - 2:
        # Refresh pad to display it within the window
        pad.refresh(0, 0, sminrow, smincol, smaxrow, smaxcol)
    else:
        for i in range(pad_height):
            pad.refresh(i, 0, sminrow, smincol, smaxrow, smaxcol)
            time.sleep(0.3)


def main(stdscr) -> None:
    # socket initialization
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sock.setblocking(False)

    # 'states' variables
    enable = ["OFF"]
    transport_filter = 0
    df = pd.DataFrame(
        columns=["number", "time", "t_captured", "mac_src", "mac_dst", "protocol", "length", "rest"]
    )
    current_row = 0
    display_start = 0
    page = 1

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

    n_display_rows = win_mid_l.getmaxyx()[0] - 3  # number of rows to display in table

    # Set box and refresh each window to draw them on the screen
    for win in [win_top, win_mid_l, win_mid_r, win_bottom]:
        win.box()
        win.refresh()

    while True:
        display_options(win_bottom)
        display_status(win_top, transport_filter, enable[0], len(df))

        display_table(win_mid_l, df, current_row, display_start, transport_filter)

        if enable[0] == "ON" or len(df) == 0:
            # shows nothing in mid-right window while the capture is ON
            win_mid_r.clear()
        elif transport_filter != 0:
            # pass a filtered dataframe as argument if capture filter is not "ALL" 
            display_more_info(win_mid_r, df[df["protocol"] == PROTOCOLS_OPTIONS[transport_filter]],
                              display_start + current_row, page)
        else:
            display_more_info(win_mid_r, df, display_start + current_row, page)

        # updates the first item index to display in table if the dataframe length is bigger than the number of rows
        # while capture is ON
        if enable[0] == "ON" and len(df) > n_display_rows:
            display_start = len(df) - n_display_rows

        # listen to key press
        try:
            key = stdscr.getch()
        except Exception:
            key = -1

        # handling key press
        if 0 <= key <= 255:
            char = chr(key).lower()
            if char == 'q':
                break
            elif char == 's':
                if enable[0] == "ON":
                    enable[0] = "OFF"
                else:
                    enable[0] = "ON"
                    threading.Thread(target=start_packet_capture, args=(enable, sock, df)).start()
            elif char == 'f':
                win_mid_l.clear()
                win_mid_l.box()
                transport_filter = (transport_filter + 1) % len(PROTOCOLS_OPTIONS)
        elif key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_UP and display_start > 0:
            display_start -= 1
        elif key == curses.KEY_DOWN and current_row < n_display_rows - 1:
            if current_row + display_start < len(df) - 1:
                current_row += 1
        elif key == curses.KEY_DOWN and display_start + n_display_rows < len(df):
            display_start += 1
        elif key == curses.KEY_RIGHT and page < 3:
            page += 1
        elif key == curses.KEY_LEFT and page > 1:
            page -= 1

        stdscr.refresh()


if __name__ == "__main__":
    curses.wrapper(main)
