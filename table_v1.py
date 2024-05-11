import curses

# Function to draw the table
def draw_table(stdscr, current_row):
    # Example data for the table
    data = [("Row 1", "Data 1"), ("Row 2", "Data 2"), ("Row 3", "Data 3")]
    h, w = stdscr.getmaxyx()
    for idx, (row_label, row_data) in enumerate(data):
        x = w//2 - 10  # Centering the table
        y = h//2 - len(data)//2 + idx
        if idx == current_row:
            stdscr.addstr(y, x, f"{row_label} {row_data}", curses.A_REVERSE)
        else:
            stdscr.addstr(y, x, f"{row_label} {row_data}")

# Function to handle the keyboard navigation
def main(stdscr):
    curses.curs_set(0)  # Hide the cursor
    current_row = 0  # Start at the first row
    draw_table(stdscr, current_row)
    stdscr.refresh()

    while True:
        key = stdscr.getch()
        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < 2:  # Assuming 3 rows for simplicity
            current_row += 1
        elif key == ord('q'):  # Press 'q' to quit
            break
        draw_table(stdscr, current_row)
        stdscr.refresh()

# Run the program
curses.wrapper(main)