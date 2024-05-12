import socket, struct, textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main() -> None:
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, adrr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + f'Dst: {dest_mac}, Src: {src_mac}, Protocol: {eth_proto}')

        # 8 for IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, dst, data = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(TAB_2 + f'Protocol: {proto}, Source: {src}, Destination: {dst}')

            if proto == 1:  # icmp
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            elif proto == 6:  # tcp
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(
                    data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination port: {dest_port}')
                print(TAB_2 + f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(TAB_2 + 'FLAGS:')
                print(
                    TAB_3 + f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            elif proto == 17:  # udp
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            else:  # other
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_1, data))


def ethernet_frame(data: bytes) -> tuple:
    """
    Unpack an Ethernet frame from the provided raw data.

    Parameters:
        data (bytes): The raw data from which the Ethernet frame will be unpacked.

    Returns:
        tuple: A tuple containing:
               - Destination MAC address (str),
               - Source MAC address (str),
               - Ethernet protocol (int),
               - Payload data (bytes).

    The function extracts the destination MAC address, source MAC address, and protocol type
    from the first 14 bytes of the frame using structured unpacking. The protocol number
    is converted from network to host byte order. The remainder of the data is the payload.
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr: bytes) -> str:
    """
    Convert a 6-byte address into a human-readable MAC address format.

    Parameters:
        bytes_addr (bytes): A 6-byte string representing the MAC address.

    Returns:
        str: A MAC address in the form of 'XX:XX:XX:XX:XX:XX' where 'XX' are hexadecimal digits.

    This function maps each byte of the input to a two-digit hexadecimal string,
    joins them with colons, and returns the result in uppercase.
    """
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def ipv4_packet(data: bytes) -> tuple:
    """
    Unpacks an IPv4 packet from the provided raw data.

    Parameters:
        data (bytes): The raw data from which the IPv4 packet will be unpacked.

    Returns:
        tuple: A tuple containing:
               - IP version (int),
               - Header length (int),
               - Time to Live (TTL, int),
               - Protocol (int),
               - Source IP address (str),
               - Destination IP address (str),
               - IP payload data (bytes).

    This function unpacks and interprets the first byte to determine the IP version
    and header length, then extracts the TTL, protocol, source IP, and destination IP
    from the subsequent bytes. The remaining bytes after the header constitute the payload.
    """
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(dst), data[header_length:]


def ipv4(addr: bytes) -> str:
    """
    Converts a 4-byte IP address into a human-readable dotted decimal format.

    Parameters:
        addr (bytes): A 4-byte string representing the IPv4 address.

    Returns:
        str: A string representation of the IPv4 address in dotted decimal format.

    Each byte of the input is mapped to a decimal number and joined by dots to format
    the address.
    """
    return '.'.join(map(str, addr))


def icmp_packet(data: bytes) -> tuple:
    """
    Unpacks an ICMP packet from the provided raw data.

    Parameters:
        data (bytes): The raw data from which the ICMP packet will be unpacked.

    Returns:
        tuple: A tuple containing:
               - ICMP type (int),
               - ICMP code (int),
               - Checksum (int),
               - ICMP payload data (bytes).

    The function unpacks the first 4 bytes to get the ICMP type, code, and checksum.
    The remainder of the data is returned as the ICMP payload.
    """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data: bytes) -> tuple:
    """
    Unpacks a TCP segment from the provided raw data.

    Parameters:
        data (bytes): The raw data from which the TCP segment will be unpacked.

    Returns:
        tuple: A tuple containing:
               - Source port (int),
               - Destination port (int),
               - Sequence number (int),
               - Acknowledgment number (int),
               - Urgent flag (bool),
               - Acknowledgment flag (bool),
               - Push function flag (bool),
               - Reset flag (bool),
               - Synchronize flag (bool),
               - Finish flag (bool),
               - TCP payload data (bytes).

    This function extracts the TCP segment header and interprets the flags from a reserved field,
    computing the data offset to determine where the payload begins.
    """
    # Unpack the first 14 bytes for basic header information and the flags
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    # Calculate the data offset
    offset = (offset_reserved_flags >> 12) * 4
    # Extract flags using bitwise operations
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    # Return unpacked data and the payload
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
        data[offset:]


def udp_segment(data: bytes) -> tuple:
    """
    Unpacks a UDP segment from the provided raw data.

    Parameters:
        data (bytes): The raw data from which the UDP segment will be unpacked.

    Returns:
        tuple: A tuple containing:
               - Source port (int),
               - Destination port (int),
               - Length of the UDP segment including header (int),
               - UDP payload data (bytes).

    This function unpacks the UDP header to extract source and destination ports, and the length,
    then returns the remainder of the data as the payload.
    """
    # Unpack the first 8 bytes for the UDP header
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    # Return unpacked data and the payload
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix: str, string: str | bytes, size: int = 80) -> str:
    """
    Formats a string or byte data into a prefixed multi-line format, wrapping the lines to a specified width.

    Parameters:
        prefix (str): A string to be prepended to each line of the formatted string.
        string (str or bytes): The input string or bytes to be formatted.
        size (int, optional): The total width for the resulting lines including the prefix. Defaults to 80.

    Returns:
        str: A string with the original content formatted with the prefix on each line, wrapped according to the specified size.

    This function converts byte data into a hexadecimal representation if needed, then breaks the data or string
    into multiple lines, ensuring each line starts with the given prefix and does not exceed the specified total width.
    """
    # Adjust the line width to account for the prefix length
    size -= len(prefix)
    # Convert bytes to a readable hex string if 'string' is bytes
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        # Adjust size to align the hex pairs correctly
        if size % 2:
            size -= 1
    # Use textwrap to handle the string wrapping and prepend the prefix to each line
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == "__main__":
    main()
