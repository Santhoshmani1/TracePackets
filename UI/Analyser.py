import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.layers.http import HTTPRequest
from lib.HttpPacket import HttpPacket
from lib.HttpsPacket import HttpsPacket
from scapy.all import Raw
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from lib.Packet import Packet
from lib.constants import get_layer
from UI.Search import Search
from UI.Quit import Quit


class PacketAnalyzerUI:
    def __init__(self, root, packet_handler):
        self.root = root
        self.packet_handler = packet_handler
        self.root.title("Packet Analyzer")
        self.create_widgets()
        self.packet_handler.start_sniffing()  # Start sniffing by default
        self.packet_map = {}  # Dictionary to store packet objects
        self.search = Search(self)

    def create_widgets(self):
        """Create the widgets for the UI and pack them to the root window"""
        self.filter_frame = ttk.Frame(self.root)
        self.filter_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.filter_label = ttk.Label(self.filter_frame, text="Filter:")
        self.filter_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.filter_entry = ttk.Entry(self.filter_frame)
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        self.apply_filter_button = ttk.Button(
            self.filter_frame, text="Apply Filter", command=self.apply_filter
        )
        self.apply_filter_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.quit_button = ttk.Button(
            self.filter_frame, text="Quit", command=self.quit_application
        )
        self.quit_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        self.tree_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.tree_frame, weight=1)

        self.tree_scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL)
        self.tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=("sn", "src", "dst", "proto", "length", "info"),
            show="headings",
            yscrollcommand=self.tree_scrollbar.set,
        )
        self.tree.heading("sn", text="Serial Number")
        self.tree.heading("src", text="Source IP")
        self.tree.heading("dst", text="Destination IP")
        self.tree.heading("proto", text="Protocol")
        self.tree.heading("length", text="Length")
        self.tree.heading("info", text="Info")
        self.tree.column("sn", width=50)
        self.tree.column("src", width=150)
        self.tree.column("dst", width=150)
        self.tree.column("proto", width=100)
        self.tree.column("length", width=100)
        self.tree.column("info", width=300)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree_scrollbar.config(command=self.tree.yview)

        self.tree.bind("<Double-1>", self.on_packet_click)

        self.details_frame = ttk.LabelFrame(self.paned_window, text="Packet Details")
        self.paned_window.add(self.details_frame, weight=1)

        self.details = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD)
        self.details.pack(fill=tk.BOTH, expand=True)

    def apply_filter(self):
        filter_text = self.filter_entry.get()
        self.search.apply_filter(filter_text)

    def update_tree(self, packets):
        """Update the tree view with the packets received from the packet handler"""
        self.tree.delete(*self.tree.get_children())
        self.packet_map.clear()  # Clear the packet map
        for index, packet in enumerate(packets, start=1):
            self.add_packet_to_tree(index, packet)

    def add_packet_to_tree(self, serial_number, packet):
        """Add a packet to the tree view"""
        if isinstance(packet, HttpPacket) or isinstance(packet, HttpsPacket):
            src = packet.src
            dst = packet.dst
            proto = packet.proto
            length = len(packet.packet)
            info = packet.info
            tree_item = self.tree.insert(
                "", tk.END, values=(serial_number, src, dst, proto, length, info)
            )
            self.packet_map[tree_item] = packet  # Store the packet object in the map

    def on_packet_click(self, event):
        """Handle the double click event on a packet in the tree view"""
        selected_item = self.tree.selection()[0]
        packet = self.packet_map[selected_item]
        self.show_packet_details(packet)

    def clear_details(self):
        """Clear the details text area in the UI to show new packet details"""
        self.details.delete(1.0, tk.END)

    def add_detail(self, key, value):
        """Add a detail to the details text area"""
        self.details.insert(tk.END, f"{key}: {value}\n")

    def show_packet_details(self, packet: Packet):
        self.clear_details()
        self.add_detail("Source IP", packet.src)
        self.add_detail("Destination IP", packet.dst)
        self.add_detail("Protocol", packet.proto)
        self.add_detail("Info", packet.info)
        if isinstance(packet, HttpPacket):
            request_headers = packet.get_request_headers()
            for key, value in request_headers.items():
                self.add_detail(key, value)
            response_headers = packet.get_response_headers()
            for key, value in response_headers.items():
                self.add_detail(key, value)
        elif isinstance(packet, HttpsPacket):
            tls_details = packet.get_tls_details()
            request_headers = packet.get_request_headers()
            for key, value in request_headers.items():
                self.add_detail(key, value)
            response_headers = packet.get_response_headers()
            for key, value in response_headers.items():
                self.add_detail(key, value)
            self.add_detail("TLS Details", tls_details)
        raw_payload = packet.get_raw_payload()
        if raw_payload:
            self.add_detail("Raw Payload (Hex)", packet.get_raw_payload_hex())
            self.add_detail(
                "Raw Payload (Plaintext)", packet.get_raw_payload_plaintext()
            )

    def quit_application(self):
        """Quit the application and stop sniffing"""
        quit_window = tk.Toplevel(self.root)
        quit_window.transient(self.root)
        quit_window.grab_set()
        Quit(quit_window, self.root, self.packet_handler)
        self.root.wait_window(quit_window)
