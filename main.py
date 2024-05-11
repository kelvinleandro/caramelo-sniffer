import curses, socket, threading
# import pandas as pd

# key options
OPTIONS = {
  "Q": "QUIT",
  "S": "START/STOP CAPTURE",
  "F": "FILTER"
}

# transport protocols
PROTOCOLS_OPTIONS = ["ALL", "TCP", "UDP", "ICMP"]

def display_options(stdscr) -> None:
  # stdscr.clear()
  h, w = stdscr.getmaxyx()
  menu_str = ""
  for key, value in OPTIONS.items():
    menu_str += f"{key} {value}  "

  # Calculating starting x to center the menu
  x = w//2 - len(menu_str)//2
  y = h // 2

  for key, value in OPTIONS.items():
    stdscr.addstr(y, x, key, curses.A_STANDOUT | curses.A_BOLD)
    x += len(key)
    stdscr.addstr(y, x, " " + value + "  ", curses.A_BOLD)
    x += len(value) + 3  # Plus 3 for the spaces (1 between key-value, 2 between items)

  stdscr.refresh()

def display_status(stdscr, proto: int, capture_state: str) -> None:
  # text colors
  curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
  curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)

  # Display updated information
  protocol_text = f"Transport Protocol: {PROTOCOLS_OPTIONS[proto]:<4}"
  stdscr.addstr(1, 2, "Capture: ")
  stdscr.addstr(1, 11, f"{capture_state:<3}", curses.color_pair(1 if capture_state == "OFF" else 2))
  stdscr.addstr(1, 17, '\t' + protocol_text)
  stdscr.refresh()

def display_table(stdscr) -> None:
  h, w = stdscr.getmaxyx()
  stdscr.addstr(h-2, 3, f"h: {h} ")
  stdscr.addstr(h-2, 10, f"w: {w}")
  stdscr.refresh()

def display_more_info(stdscr) -> None:
  # Show other info in mid-right screen
  # TODO: Page 1/3: Internet Protocol
  # TODO: Page 2/3: Transport Protocol
  # TODO: Page 3/3: show "non-converted" bytes (scrolling up automatically)
  pass

def capture_packets(enable: list, sock: socket.socket, counter: list) -> None:
  if enable[0] == "ON":
    try:
      raw_data, adrr = sock.recvfrom(65535)
      if raw_data: 
        counter[0] += 1
    except BlockingIOError:
      pass # No packets to read, move on

def start_packet_capture(enable: list, sock: socket.socket, counter: list) -> None:
  while enable[0] == "ON":
    capture_packets(enable, sock, counter)

def main(stdscr) -> None:
  sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  sock.setblocking(False)
  counter = [0]
  start_stop_state = ["OFF"]
  transport_filter = 0

  stdscr.refresh()
  curses.curs_set(0)  # Hide the cursor
  stdscr.nodelay(True)
  MAX_HEIGHT, MAX_WIDTH = stdscr.getmaxyx() # Screen max width and height  

  # Create top window
  win_top = curses.newwin(int(MAX_HEIGHT * 0.10), MAX_WIDTH, 0, 0)

  # Create middle-left window
  win_mid_l = curses.newwin(int(MAX_HEIGHT * 0.80), int(MAX_WIDTH * 0.70), int(MAX_HEIGHT * 0.10), 0)

  # Create middle-right window
  win_mid_r = curses.newwin(int(MAX_HEIGHT * 0.80), int(MAX_WIDTH * 0.30), int(MAX_HEIGHT * 0.10), int(MAX_WIDTH * 0.70))

  # Create bottom window
  win_bottom = curses.newwin(int(MAX_HEIGHT * 0.10), MAX_WIDTH, int(MAX_HEIGHT * 0.90), 0)

  # Set box and refresh each window to draw them on the screen
  for win in [win_top, win_mid_l, win_mid_r, win_bottom]:
    win.box()
    win.refresh()

  while True:
    # stdscr.clear()
    display_options(win_bottom)
    display_status(win_top, transport_filter, start_stop_state[0])

    display_table(win_mid_l)

    if start_stop_state[0] == "ON":
      win_mid_l.addstr(2, 5, f"Packets captured: {counter[0]}")
      win_mid_l.refresh()

    try:
      key = stdscr.getch()
    except:
      key = None

    if key == ord('q'):
      break  # Exit the loop if 'Q' is pressed
    elif key == ord('s'):
      if start_stop_state[0] == "ON":
        start_stop_state[0] = "OFF"
      else:
        start_stop_state[0] = "ON"
        threading.Thread(target=start_packet_capture, args=(start_stop_state, sock, counter)).start()
    elif key == ord('f'):
      # Cycle through the elements
      transport_filter = (transport_filter + 1) % len(PROTOCOLS_OPTIONS)

    stdscr.refresh()

if __name__ == "__main__":
  curses.wrapper(main)