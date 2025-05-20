from monitor.packet_sniffer import start_sniffing,simulate_attack

if __name__ == "__main__":
    print("Starting real-time intrusion detection...")
    # Start sniffing packets
    simulate_attack()

    # Then start sniffing normally
    start_sniffing()
