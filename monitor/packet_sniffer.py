# monitor/sniffer.py
from scapy.all import sniff, IP, get_if_list
from detection.classifier import classify_packet
from firewall.block_ip import block_ip
from datetime import datetime
import logging
import os

# Setup logging
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "attack_log.txt")
logging.basicConfig(
    filename=log_file, level=logging.INFO, format="%(asctime)s - %(message)s"
)


def extract_features(packet):
    """
    Extract features from the packet for the IDS model.
    You should replace this placeholder with real feature extraction logic
    according to your trained model’s expected input.
    """
    try:
        # Example placeholder features:
        # Customize to extract actual NSL-KDD or your model's features from packet
        features = [
            0,  # duration
            0,  # protocol_type (e.g. tcp=0)
            0,  # service (e.g. http=0)
            0,  # flag
            len(packet),  # src_bytes (packet size)
            0,  # dst_bytes
            # Add more fields as needed to match your model input size
        ]
        # Fill up to your model’s feature vector length (e.g., 41 features)
        while len(features) < 41:
            features.append(0)
        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None


def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        print(f"Packet from {src_ip}: {packet.summary()}")  # <-- DEBUG INFO
        features = extract_features(packet)
        if features:
            attack_type = classify_packet(features)
            if attack_type != "Normal":
                log_msg = f"ALERT: Intrusion Detected from IP {src_ip} — Type: {attack_type} — Action Taken: IP Blocked"
                print(log_msg)
                logging.info(log_msg)
                block_ip(src_ip)


def simulate_attack():
    from scapy.all import IP, TCP  # if not imported yet

    # Create a fake packet with IP layer (source IP is attacker)
    fake_packet = IP(src="192.168.1.100", dst="192.168.1.50") / TCP()

    features = extract_features(fake_packet)

    # For test purpose, forcibly assign an attack type, e.g., "DoS"
    attack_type = "DoS"

    if attack_type != "Normal":
        log_msg = f"ALERT: Intrusion Detected from IP {fake_packet[IP].src} — Type: {attack_type} — Action Taken: IP Blocked"
        print(log_msg)
        logging.info(log_msg)
        block_ip(fake_packet[IP].src)


def start_sniffing():
    interfaces = get_if_list()
    print("Available interfaces:", interfaces)

    if not interfaces:
        print("No network interfaces found! Please check your system.")
        return

    # Choose the first interface or specify one manually here:
    iface = interfaces[0]
    print(f"Starting sniffing on interface: {iface}")

    sniff(prn=process_packet, store=0, iface=iface)
