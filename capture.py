import socket
import struct
import time

import pandas


def capture_packets(enable: list, sock: socket.socket, df: pandas.DataFrame) -> None:
    if enable[0] == "ON":
        try:
            raw_data, _ = sock.recvfrom(65535)
            t = time.time()
            if raw_data:
                mac_dst, mac_src, eth_proto, eth_data = ethernet_frame(raw_data)
                transport_protocol = ""
                rest = None

                # 8 for IPv4
                if eth_proto == 8:
                    version, header_length, ttl, protocol, ip_src, ip_dst, ip_data = ipv4_packet(eth_data)
                    rest = {"version": version, "header_length": header_length, "ttl": ttl, "ip_src": ip_src,
                            "ip_dst": ip_dst}
                    if protocol == 1:
                        transport_protocol = "ICMP"
                        icmp_type, icmp_code, checksum, transport_data = icmp_packet(ip_data)
                        rest.update({"icmp_type": icmp_type, "icmp_code": icmp_code, "checksum": checksum,
                                     "payload": transport_data})
                    elif protocol == 6:
                        transport_protocol = "TCP"
                        src_port, dst_port, sequence_number, acknowledgment_number, flags, transport_data = tcp_segment(
                            ip_data)
                        rest.update({"port_src": src_port, "port_dst": dst_port, "sequence_number": sequence_number,
                                     "acknowledgment_number": acknowledgment_number, "flags": flags,
                                     "payload": transport_data})
                    elif protocol == 17:
                        transport_protocol = "UDP"
                        src_port, dst_port, length, transport_data = udp_segment(ip_data)
                        rest.update(
                            {"port_src": src_port, "port_dst": dst_port, "length": length, "payload": transport_data})
                    else:
                        transport_protocol = f"{protocol}"
                        rest.update({"payload": ip_data})

                # cols: ["number", "time", "t_captured", "mac_src", "mac_dst", "protocol", "length", "rest"]
                row = [len(df) + 1, None, t, mac_src, mac_dst, transport_protocol, len(raw_data), rest]
                df.loc[len(df)] = row
                df.at[df.index[-1], 'time'] = t - df.at[df.index[0], 't_captured']
        except BlockingIOError:
            pass  # No packets to read, move on


def start_packet_capture(enable: list, sock: socket.socket, df: pandas.DataFrame) -> None:
    while enable[0] == "ON":
        capture_packets(enable, sock, df)


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
    icmp_type, icmp_code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, icmp_code, checksum, data[4:]


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
               - A dictionary of flags including:
                      'URG' (bool): Urgent flag,
                      'ACK' (bool): Acknowledgment flag,
                      'PSH' (bool): Push function flag,
                      'RST' (bool): Reset flag,
                      'SYN' (bool): Synchronize flag,
                      'FIN' (bool): Finish flag,
               - TCP payload data (bytes).

    This function extracts the TCP segment header and interprets the flags from a reserved field,
    computing the data offset to determine where the payload begins.
    """
    # Unpack the first 14 bytes for basic header information and the flags
    src_port, dst_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    # Calculate the data offset
    offset = (offset_reserved_flags >> 12) * 4
    # Extract flags using bitwise operations
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    flags = {
        "URG": flag_urg,
        "ACK": flag_ack,
        "PSH": flag_psh,
        "RST": flag_rst,
        "SYN": flag_syn,
        "FIN": flag_fin,
    }
    # Return unpacked data and the payload
    return src_port, dst_port, sequence, acknowledgment, flags, data[offset:]


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
