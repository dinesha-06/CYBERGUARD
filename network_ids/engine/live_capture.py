
import re
import subprocess
from pathlib import Path



import re
import subprocess


def list_windump_interfaces(windump_path="windump"):
    """Return WinDump interfaces as (number, device_path, description)."""

    result = subprocess.run(
        [windump_path, "-D"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    output = (result.stdout or "") + "\n" + (result.stderr or "")

    if result.returncode != 0:
        raise RuntimeError(f"WinDump -D failed:\n{output}")

    interfaces = []

    for line in output.splitlines():
        match = re.match(
            r"^\s*(\d+)\.\s+(\S+)\s*(?:\((.*?)\))?\s*$",
            line.strip(),
        )
        if match:
            interfaces.append({
                "number": int(match.group(1)),
                "device": match.group(2),
                "description": match.group(3) or "",
            })

    return interfaces




import re


import re
import subprocess


def detect_windump_interface(
    windump_path=r"C:\WinDump\windump.EXE",
    adapter_name="Realtek 8852BE-VT Wireless LAN WiFi 6 PCI-E NIC",
):
    """Discover the current interface number from raw WinDump output."""

    result = subprocess.run(
        [windump_path, "-D"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"WinDump -D failed:\n{result.stdout}\n{result.stderr}"
        )

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    matches = []

    for line in output.splitlines():
        # Example:
        # 4.\Device\NPF_{GUID} (Realtek ... NIC)
        match = re.match(r"^\s*(\d+)\.(.*?)\s*$", line)

        if not match:
            continue

        number = int(match.group(1))
        remainder = match.group(2)

        # Extract the description from the final parentheses.
        description_match = re.search(r"\((.*)\)\s*$", remainder)

        if not description_match:
            continue

        description = description_match.group(1).strip()

        # Exact match avoids selecting adapters ending in #2 or #3.
        if description.casefold() == adapter_name.casefold():
            matches.append({
                "number": number,
                "description": description,
                "line": line.strip(),
            })

    if len(matches) != 1:
        print("Raw WinDump interface listing:")
        print(output)

        raise RuntimeError(
            f"Expected one exact match for {adapter_name!r}; "
            f"found {len(matches)}."
        )

    selected = matches[0]
    print(f"Detected interface number: {selected['number']}")
    print(f"Adapter: {selected['description']}")
    print(f"WinDump entry: {selected['line']}")

    return selected["number"]


def start_live_capture(
    output_pcap,
    duration_seconds=60,
    windump_path="windump",
    adapter_name="Realtek 8852BE-VT Wireless LAN WiFi 6 PCI-E NIC",
):
    """
    Capture traffic for a fixed duration using the detected interface.

    The output PCAP can subsequently be processed by CICFlowMeter.
    """
    output_pcap = Path(output_pcap).resolve()
    output_pcap.parent.mkdir(parents=True, exist_ok=True)

    interface_number = detect_windump_interface(
        windump_path=windump_path,
        adapter_name=adapter_name,
    )

    command = [
        windump_path,
        "-i", str(interface_number),
        "-w", str(output_pcap),
    ]

    print(f"Starting capture on interface {interface_number}")
    print(f"Output: {output_pcap}")
    print(f"Duration: {duration_seconds} seconds")

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        try:
            process.wait(timeout=duration_seconds)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    except KeyboardInterrupt:
        if process.poll() is None:
            process.terminate()
            process.wait()
        print("Capture stopped by user.")

    if output_pcap.exists():
        print(f"Capture file created: {output_pcap}")
    else:
        print("Warning: no capture file was created.")

    return output_pcap
