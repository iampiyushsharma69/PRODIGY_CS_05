
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
import socket
from datetime import datetime
import os

running = False
sniffer_thread = None

# Set log file path
documents_path = os.path.join(os.path.expanduser("~"), "Documents")
log_file_path = os.path.join(documents_path, "packet_log.txt")

# Clear or create log file
with open(log_file_path, "w") as log_file:
    log_file.write(f"Packet Capture Log - {datetime.now()}\n\n")

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        src_host = resolve_host(src_ip)
        dst_host = resolve_host(dst_ip)

        src_port = dst_port = "-"
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        payload_size = len(packet[Raw].load) if Raw in packet else 0

        info = f"{src_ip}:{src_port} ({src_host}) -> {dst_ip}:{dst_port} ({dst_host}) | Proto: {proto} | Payload: {payload_size} bytes\n"
        output_text.insert(tk.END, info)
        output_text.see(tk.END)

        with open(log_file_path, "a") as log_file:
            log_file.write(info)

def resolve_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def start_sniffing():
    global running, sniffer_thread
    if not running:
        running = True
        sniffer_thread = threading.Thread(target=lambda: sniff(prn=process_packet, store=False))
        sniffer_thread.start()
        status_label.config(text="Status: Running", fg="green")

def stop_sniffing():
    global running
    running = False
    status_label.config(text="Status: Stopped", fg="red")

# GUI Setup
app = tk.Tk()
app.title("Advanced Network Packet Analyzer")
app.geometry("700x500")
app.configure(bg="#f0f2f5")

title = tk.Label(app, text="Advanced Network Packet Analyzer", font=("Helvetica", 16, "bold"), bg="#f0f2f5")
title.pack(pady=10)

start_btn = tk.Button(app, text="Start Capture", bg="#4CAF50", fg="white", width=20, command=start_sniffing)
start_btn.pack(pady=5)

stop_btn = tk.Button(app, text="Stop Capture", bg="#f44336", fg="white", width=20, command=stop_sniffing)
stop_btn.pack(pady=5)

status_label = tk.Label(app, text="Status: Stopped", font=("Helvetica", 12), bg="#f0f2f5", fg="red")
status_label.pack(pady=5)

path_label = tk.Label(app, text=f"Log file: {log_file_path}", bg="#f0f2f5", fg="blue", wraplength=680)
path_label.pack(pady=5)

output_text = scrolledtext.ScrolledText(app, width=85, height=20, bg="white")
output_text.pack(pady=10)

app.mainloop()
