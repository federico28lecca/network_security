
import re
import subprocess

from pathlib import Path


PCAP_FILE = Path(__file__).resolve().parent / "capture-5.pcap"

JA4 = "t13d1516h2_8daaf6152771_9829734ff3cf"
EXPECTED_CONNECTIONS = 8


def extract_connections(pcap_file, fingerprint):
    """
    Extract TLS connections matching the malware's JA4 fingerprint.

    Args:
        pcap_file (Path): Path to the PCAP capture.
        fingerprint (str): JA4 fingerprint of the malware.

    Returns:
        list: Tuples containing frame number, source IP and SNI.
    """
    if not pcap_file.is_file():
        raise FileNotFoundError(f"PCAP not found: {pcap_file}")

    # Run TShark and extract the required TLS fields.
    command = [
        "tshark",
        "-r", str(pcap_file),
        "-Y", f'tls.handshake.type == 1 && tls.handshake.ja4 == "{fingerprint}"',
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tls.handshake.extensions_server_name"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    connections = []

    # Parse each line of the TShark output.
    for line in result.stdout.splitlines():
        fields = line.split("\t")

        if len(fields) != 3:
            raise ValueError(f"Unexpected TShark output: {line!r}")

        frame, source_ip, sni = (
            field.strip() for field in fields
        )

        if not frame.isdigit() or not source_ip or not sni:
            raise ValueError(f"Incomplete TShark output: {line!r}")

        connections.append((
            int(frame),
            source_ip,
            sni.lower().rstrip(".")
        ))

    # Ensure connections are ordered by capture position.
    return sorted(connections, key=lambda entry: entry[0])


def build_flag(connections):
    """
    Reconstruct the flag from the first label of each SNI.

    Args:
        connections (list): TLS connections in capture order.

    Returns:
        str: The reconstructed netsec flag.
    """
    if len(connections) != EXPECTED_CONNECTIONS:
        raise ValueError(
            f"Expected 8 connections, found {len(connections)}"
        )

    # Verify the presence of exactly one known C2 connection.
    c2_count = sum(
        sni.endswith(".syncbridge.example")
        for _, _, sni in connections
    )

    if c2_count != 1:
        raise ValueError("Expected exactly one known C2 connection.")

    fragments = []

    for _, _, sni in connections:
        # Extract the first label of the SNI.
        fragment = sni.split(".", 1)[0]

        # Validate the six-character hexadecimal fragment.
        if re.fullmatch(r"[0-9a-f]{6}", fragment) is None:
            raise ValueError(f"Invalid SNI fragment: {sni}")

        fragments.append(fragment)

    # Concatenate all fragments in capture order.
    token = "".join(fragments)

    return f"netsec{{{token}}}"


def main():
    """Identify malware connections and reconstruct the flag."""
    connections = extract_connections(PCAP_FILE, JA4)

    print(f"Malware connections: {len(connections)}")

    for frame, source_ip, sni in connections:
        print(f"Frame {frame}: {source_ip} -> {sni}")

    flag = build_flag(connections)

    print(f"\nFlag: {flag}")


if __name__ == "__main__":
    main()
