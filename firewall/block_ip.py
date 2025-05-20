import subprocess
import platform

TEST_MODE = True  # Set False to enable actual blocking


def block_ip(ip_address: str):
    """
    Blocks the given IP address on the local machine's firewall.
    Supports Linux (iptables) and Windows (netsh).

    Parameters:
        ip_address (str): The IP address to block.
    """

    if TEST_MODE:
        print(f"[TEST MODE] Simulated block of IP: {ip_address}")
        return

    system = platform.system().lower()
    try:
        if "linux" in system:
            # Use iptables to drop packets from the IP
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=True,
            )
        elif "windows" in system:
            # Use netsh to add a firewall rule to block the IP
            subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=BlockIP",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip_address}",
                ],
                check=True,
            )
        else:
            print(f"[!] Unsupported OS for blocking IP: {system}")
            return

        print(f"[!] Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to block IP {ip_address}: {e}")
