import curses

# Sample data for the table with more entries
data = ["Row 1", "Row 2", "Row 3", "Row 4", "Row 5", "Row 6", "Row 7", "Row 8", "Row 9", "Row 10"]

def draw_table(stdscr, selected_row_idx, top_visible_row):
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    num_rows_to_show = 4  # Number of rows visible at a time
    for idx in range(num_rows_to_show):
        row_text = data[top_visible_row + idx]
        x = w//2 - len(row_text)//2
        y = h//2 - num_rows_to_show//2 + idx
        if top_visible_row + idx == selected_row_idx:
            stdscr.addstr(y, x, row_text, curses.A_REVERSE)
        else:
            stdscr.addstr(y, x, row_text)
    stdscr.refresh()

def main(stdscr):
    curses.curs_set(0)
    selected_row_idx = 0
    top_visible_row = 0
    num_rows_to_show = 4

    while True:
        draw_table(stdscr, selected_row_idx, top_visible_row)

        key = stdscr.getch()

        if key == curses.KEY_UP and selected_row_idx > 0:
            selected_row_idx -= 1
            if selected_row_idx < top_visible_row:
                top_visible_row = selected_row_idx
        elif key == curses.KEY_DOWN and selected_row_idx < len(data) - 1:
            selected_row_idx += 1
            if selected_row_idx >= top_visible_row + num_rows_to_show:
                top_visible_row = selected_row_idx - num_rows_to_show + 1
        elif key == ord('q'):
            break


curses.wrapper(main)