def center_string(text: str, length: int) -> str:
    if len(str(text)) >= length:
        return str(text)[:length - 3] + "..."
    else:
        return f"{text:^{length}}"


def generate_table_line(line, cols_dim: dict) -> str:
    values = [line["number"], line["time"], line["mac_src"], line["mac_dst"], line["protocol"], line["length"]]
    length = list(cols_dim.values())
    line_str = "|".join(center_string(values[i], length[i]) for i in range(len(values)))
    return line_str


def select_line_color(line) -> int:
    protocol = line["protocol"]
    match protocol:
        case "TCP":
            proto_color = 3
        case "UDP":
            proto_color = 4
        case "ICMP":
            proto_color = 5
        case _:
            proto_color = 0
    return proto_color
