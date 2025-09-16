#!/usr/bin/env python3
# simple_chat.py using UDP port
from scapy.all import *
import threading
import time

# Configuration
MY_IP = "192.168.80.131"  # Replace with your local IP
PEER_IP = "192.168.80.132"  # Replace with the peer's IP
CHAT_PORT = 12345  # UDP port for chat
INTERFACE = "ens33"  # Replace with your network interface (e.g., "wlan0", "en0")

# Function to send chat messages
def send_messages():
    while True:
        message = input("You: ")  # Get user input
        if message.lower() == "exit":
            print("Chat ended.")
            break
        # Create and send a UDP packet with the message as payload
        packet = IP(dst=PEER_IP) / UDP(sport=CHAT_PORT, dport=CHAT_PORT) / Raw(load=message)
        send(packet, iface=INTERFACE, verbose=False)
        time.sleep(0.1)  # Small delay to prevent overwhelming the network

# Function to receive chat messages
def receive_messages():
    def packet_filter(pkt):
        # Filter packets: UDP, from peer, to us, on the correct port
        return (IP in pkt and UDP in pkt and
                pkt[IP].src == PEER_IP and pkt[IP].dst == MY_IP and
                pkt[UDP].sport == CHAT_PORT and pkt[UDP].dport == CHAT_PORT)

    def handle_packet(pkt):
        if Raw in pkt:
            print(f"\nPeer: {pkt[Raw].load.decode('utf-8', errors='ignore')}\nYou: ", end="")

    # Sniff packets matching the filter
    sniff(iface=INTERFACE, filter=f"udp port {CHAT_PORT}", prn=handle_packet, lfilter=packet_filter)

# Main function to start the chat
def main():
    print("Starting bidirectional chat. Type 'exit' to quit.")
    print(f"Chatting with {PEER_IP} on port {CHAT_PORT} via {INTERFACE}")

    # Start the receiver in a separate thread
    receiver_thread = threading.Thread(target=receive_messages, daemon=True)
    receiver_thread.start()

    # Start the sender in the main thread
    send_messages()

if __name__ == "__main__":
    main()
