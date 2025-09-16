#!/usr/bin/env python3
# # simple_chat.py using UDP port

from scapy.all import IP, ICMP, Raw, send, sniff
import threading
import time
import os
import sys

# Configuration
MY_IP = "192.168.80.131"  # Replace with your local IP
PEER_IP = "192.168.80.132"  # Replace with the peer's IP
INTERFACE = "eth0"  # Replace with your network interface (e.g., "wlan0", "en0")


# Function to send chat messages via ICMP Echo Request
def send_messages():
    # Note: Sending raw ICMP packets usually requires root privileges
    while True:
        message = input("You: ")  # Get user input
        if message.lower() == "exit":
            print("Chat ended.")
            break
        # Create and send an ICMP Echo Request with the message as payload
        packet = IP(dst=PEER_IP) / ICMP(type="echo-request") / Raw(load=message.encode('utf-8'))
        send(packet, iface=INTERFACE, verbose=False)
        time.sleep(0.05)  # Small delay to prevent overwhelming the network


# Function to receive chat messages via ICMP Echo Reply or Echo Request from peer
def receive_messages():
    def packet_filter(pkt):
        # Filter packets: must be IP+ICMP from peer to us (either request or reply)
        if IP in pkt and ICMP in pkt:
            try:
                if pkt[IP].src == PEER_IP and pkt[IP].dst == MY_IP:
                    # Only accept echo-request or echo-reply
                    if pkt[ICMP].type in (8, 0):
                        return True
            except Exception:
                return False
        return False

    def handle_packet(pkt):
        if Raw in pkt:
            payload = pkt[Raw].load
            try:
                text = payload.decode('utf-8', errors='ignore')
            except Exception:
                text = str(payload)
            # If this is an Echo Request (type 8), print and send an Echo Reply back containing the same payload.
            if pkt[ICMP].type == 8:
                print(f"\nPeer (request): {text}\nYou: ", end="")
                # Build an ICMP Echo Reply with the same payload and send it back
                reply = IP(dst=PEER_IP, src=MY_IP) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / Raw(load=payload)
                send(reply, iface=INTERFACE, verbose=False)
            else:
                # Echo Reply
                print(f"\nPeer (reply): {text}\nYou: ", end="")

    # Sniff packets matching the filter (ICMP only)
    # BPF filter for ICMP helps performance; additional filtering is done in lfilter
    sniff(iface=INTERFACE, filter="icmp", prn=handle_packet, lfilter=packet_filter)

# Main function to start the chat
def main():
    # Must be root to send/receive raw ICMP packets on most systems
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("This script requires root to send/receive raw ICMP packets. Please run with sudo or as root.")
        sys.exit(1)

    print("Starting bidirectional chat. Type 'exit' to quit.")
    print(f"Chatting with {PEER_IP} via {INTERFACE}")

    # Start the receiver in a separate thread
    receiver_thread = threading.Thread(target=receive_messages, daemon=True)
    receiver_thread.start()

    # Start the sender in the main thread
    send_messages()

if __name__ == "__main__":
    main()
