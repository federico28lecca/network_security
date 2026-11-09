
import re

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP


PCAP_FILE = "capture-5.pcap"
CLIENT_IP = "198.51.100.7"
ADMIN_FRAME = 2613
TOLERANCE = 100


def extract_syn_packets():
    """
    Extract initial TCP SYN packets containing a TCP Timestamp.

    Returns:
        list: SYN packet information (frame, time, port, TSval).
    """
    syn_packets = []

    with PcapReader(PCAP_FILE) as capture:
        start_time = None

        for frame_number, packet in enumerate(capture, start=1):
            if start_time is None:
                start_time = float(packet.time)

            if IP not in packet or TCP not in packet:
                continue

            ip = packet[IP]
            tcp = packet[TCP]

            # Keep only initial SYN packets from the NAT.
            if ip.src != CLIENT_IP:
                continue

            if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
                continue

            # Extract the TCP Timestamp value.
            tsval = None

            for name, value in tcp.options:
                if name == "Timestamp":
                    tsval = value[0]
                    break

            if tsval is None:
                continue

            syn_packets.append({
                "frame": frame_number,
                "time": float(packet.time) - start_time,
                "port": tcp.sport,
                "tsval": tsval
            })

    return syn_packets


def timestamp_error(entry, anchor, hz=1000):
    """
    Calculate the timestamp error using an assumed TCP clock frequency.

    Args:
        entry (dict): SYN packet to analyze.
        anchor (dict): Reference SYN packet from the admin PC.
        hz (float): Assumed TCP clock frequency.

    Returns:
        float: Difference between observed and expected TSval.
    """
    elapsed = entry["time"] - anchor["time"]

    predicted = anchor["tsval"] + hz * elapsed

    return entry["tsval"] - predicted


def estimate_clock(connections, anchor):
    """
    Estimate the TCP clock frequency using linear regression.

    Args:
        connections (list): SYN packets from the admin PC.
        anchor (dict): Reference SYN packet.

    Returns:
        tuple: Estimated clock frequency and offset.
    """
    # Calculate time and timestamp differences from the anchor.
    x = [
        entry["time"] - anchor["time"]
        for entry in connections
    ]

    y = [
        entry["tsval"] - anchor["tsval"]
        for entry in connections
    ]

    mean_x = sum(x) / len(x)
    mean_y = sum(y) / len(y)

    # Calculate the slope using least squares.
    numerator = sum(
        (xi - mean_x) * (yi - mean_y)
        for xi, yi in zip(x, y)
    )

    denominator = sum(
        (xi - mean_x) ** 2
        for xi in x
    )

    hz = numerator / denominator
    offset = mean_y - hz * mean_x

    return hz, offset


def refined_timestamp_error(entry, anchor, hz, offset):
    """
    Calculate the timestamp error using the estimated TCP clock.

    Args:
        entry (dict): SYN packet to analyze.
        anchor (dict): Reference SYN packet.
        hz (float): Estimated TCP clock frequency.
        offset (float): Estimated clock offset.

    Returns:
        float: Residual timestamp error in ticks.
    """
    elapsed = entry["time"] - anchor["time"]

    predicted = anchor["tsval"] + hz * elapsed + offset

    return entry["tsval"] - predicted


def extract_admin_traces(admin_ports):
    """
    Extract X-Trace headers from the admin PC's HTTP requests.

    Args:
        admin_ports (set): Source ports used by the admin PC.

    Returns:
        list: Extracted X-Trace indices and hexadecimal fragments.
    """
    traces = []

    with PcapReader(PCAP_FILE) as capture:
        for frame_number, packet in enumerate(capture, start=1):
            if IP not in packet or TCP not in packet:
                continue

            ip = packet[IP]
            tcp = packet[TCP]

            # Keep only packets from the identified connections.
            if ip.src != CLIENT_IP or tcp.sport not in admin_ports:
                continue

            # Extract the TCP payload.
            payload = bytes(tcp.payload)

            if not payload:
                continue

            # Separate HTTP headers from the message body.
            headers = payload.split(b"\r\n\r\n", 1)[0]

            # Search for the X-Trace header.
            match = re.search(
                rb"(?im)^X-Trace:[ \t]*([1-8])-([0-9a-f]{6})\r?$",
                headers
            )

            if match is None:
                continue

            traces.append({
                "frame": frame_number,
                "port": tcp.sport,
                "n": int(match.group(1)),
                "fragment": match.group(2).decode("ascii").lower()
            })

    return traces


def main():
    """
    Identify the admin PC, extract its X-Trace fragments
    and reconstruct the final flag.
    """
    # Extract SYN packets and find the admin reference.
    syn_connections = extract_syn_packets()

    admin_syn = next(
        (
            entry for entry in syn_connections
            if entry["frame"] == ADMIN_FRAME
        ),
        None
    )

    if admin_syn is None:
        raise ValueError("Admin SYN packet not found.")

    # Identify connections sharing the admin's TCP clock.
    admin_connections = [
        entry for entry in syn_connections
        if abs(timestamp_error(entry, admin_syn)) < TOLERANCE
    ]

    # Estimate the actual clock frequency and its residual errors.
    hz, offset = estimate_clock(admin_connections, admin_syn)

    errors = [
        abs(refined_timestamp_error(entry, admin_syn, hz, offset))
        for entry in admin_connections
    ]

    # Extract X-Trace headers from the identified connections.
    admin_ports = {
        entry["port"] for entry in admin_connections
    }

    traces = extract_admin_traces(admin_ports)

    # Group fragments by index and check for conflicting values.
    fragments = {}

    for trace in traces:
        n = trace["n"]
        fragment = trace["fragment"]

        if n in fragments and fragments[n] != fragment:
            raise ValueError(f"Conflicting X-Trace at index {n}")

        fragments[n] = fragment

    # Verify that all eight fragments have been recovered.
    if set(fragments) != set(range(1, 9)):
        raise ValueError("Missing X-Trace fragments")

    # Sort and concatenate the fragments to reconstruct the flag.
    token = "".join(fragments[n] for n in range(1, 9))

    assert len(token) == 48

    flag = f"netsec{{{token}}}"

    # Display the analysis results.
    print(f"TCP SYN with timestamps: {len(syn_connections)}")
    print(f"Admin PC connections: {len(admin_connections)}")
    print(f"Estimated clock: {hz:.6f} Hz")
    print(f"Maximum residual error: {max(errors):.3f} ticks")
    print(f"HTTP X-Trace headers: {len(traces)}")

    print("\nUnique fragments:")
    for n in range(1, 9):
        print(f"{n}: {fragments[n]}")

    print(f"\nFlag: {flag}")


if __name__ == "__main__":
    main()
