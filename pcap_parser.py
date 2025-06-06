from scapy.all import rdpcap

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    extracted_data = []

    for pkt in packets:
        if pkt.haslayer("IP"):
            data = {
                "src": pkt["IP"].src,
                "dst": pkt["IP"].dst,
                "proto": pkt["IP"].proto,
                "len": len(pkt),
                "timestamp": pkt.time  # ⏰ UNIX timestamp
            }
            extracted_data.append(data)

    return extracted_data
