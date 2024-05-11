def center_string(text: str, length: int) -> str:
    if len(text) >= length:
        return text[:length - 3] + "..."
    else:
        return f"{text:^{length}}"
        # spaces = length - len(text)
        # left_spaces = spaces // 2
        # right_spaces = spaces - left_spaces
        # return " " * left_spaces + text + " " * right_spaces
