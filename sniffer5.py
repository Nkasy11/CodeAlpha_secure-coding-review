from scapy.all import sniff, IP, TCP, UDP, ICMP

# function tomprocess each packet
def packet_handler(packet):
    if IP in packet:
        src_ip = pcket[IP].src
        dst_ip = pcket[IP].dst
        proto = pcket[IP].proto
        print(f"Packet: SRC={src_ip}, DST={dst_ip}, PROTOCOL={proto}")
       
    if TCP in packet:
           print(f"TCP Packet: SRC-PORT={packet[TCP].sport}, DST-PORT={packet[TCP].dport}")
    elif UDP in packet:
           print(f"UDP Packet: SRC-PORT={packet[UDP].sport}, DST-PORT={packet[UDP].dport}")
    elif ICMP in packet:
           print("ICMP Packet Detected")
    else:
        print("Non-IP Packet Captured")
if __name__ == "__main__":
    print("Starting network monitoring...")
    sniff(prn=packet_handler, store=0)
     
