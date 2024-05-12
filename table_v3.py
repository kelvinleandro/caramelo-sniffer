import curses
import pandas as pd

def main(stdscr):
    # Sample DataFrame with one column
    df = pd.DataFrame({"Data": [f"Item {i}" for i in range(1, 101)]})  # Larger data set for demonstration

    # Initial settings
    curses.curs_set(0)  # Hide the cursor
    num_rows, _ = stdscr.getmaxyx()
    current_row = 0
    display_start = 0
    n_display_rows = 4  # Number of rows to display

    def display_table():
        stdscr.clear()
        for i in range(n_display_rows):
            if display_start + i < len(df):
                item = df.iloc[display_start + i]["Data"]
                if i == current_row:
                    stdscr.addstr(i, 0, item, curses.A_REVERSE)
                else:
                    stdscr.addstr(i, 0, item)
        stdscr.refresh()

    display_table()

    while True:
        key = stdscr.getch()
        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
            display_table()
        elif key == curses.KEY_UP and display_start > 0:
            display_start -= 1
            display_table()
        elif key == curses.KEY_DOWN and current_row < n_display_rows - 1:
            if current_row + display_start < len(df) - 1:
                current_row += 1
                display_table()
        elif key == curses.KEY_DOWN and display_start + n_display_rows < len(df):
            display_start += 1
            display_table()

curses.wrapper(main)
