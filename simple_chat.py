#!/usr/bin/env python3
# simple_chat.py using UDP port
from scapy.all import *
import threading
import time

# Configuration
MY_IP = "192.168.254.129"   # Replace with your local IP
PEER_IP = "192.168.254.130" # Replace with the peer's IP
CHAT_PORT = 12345          # UDP port for chat
INTERFACE = "ens33"        # Replace with your network interface (e.g., "wlan0", "en0")

# Function to send chat messages
def send_messages():
    while True:
        try:
            message = input("You: ")  # Get user input
        except EOFError:
            break
        if message.lower() == "exit":
            print("Chat ended.")
            break
        packet = IP(dst=PEER_IP) / ICMP(type=8, code=0) / Raw(load=message)
        send(packet, iface=INTERFACE, verbose=False)
        time.sleep(0.1)

# Function to receive chat messages
def receive_messages():
    def handle_packet(pkt):
        if IP in pkt and ICMP in pkt and pkt[IP].src == PEER_IP:
            if pkt[ICMP].type in [0, 8]:  # Echo Reply or Echo Request
                if Raw in pkt:
                    msg = pkt[Raw].load.decode("utf-8", errors="ignore")
                    print(f"\nPeer: {msg}\nYou: ", end="", flush=True)
    sniff(
        iface=INTERFACE,
        filter="icmp",
        prn=handle_packet,
        store=False,
    )

# Main function
def main():
    print("Starting bidirectional chat. Type 'exit' to quit.")
    print(f"Chatting with {PEER_IP} on port {CHAT_PORT} via {INTERFACE}")

    receiver_thread = threading.Thread(target=receive_messages, daemon=True)
    receiver_thread.start()

    send_messages()

if __name__ == "__main__":
    main()
