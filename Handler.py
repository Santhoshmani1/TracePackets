import threading
from scapy.all import sniff
from lib.HttpPacket import HttpPacket
from lib.HttpsPacket import HttpsPacket


class PacketHandler:
    def __init__(self):
        self.all_packets = []
        self.filtered_packets = []
        self.current_filter = ""
        self.ui = None
        self.index = 1  # Initialize the index

    def set_ui(self, ui):
        self.ui = ui

    def packet_callback(self, packet):
        if packet.haslayer("HTTP"):
            http_request = HttpPacket(packet)
            self.all_packets.append(http_request)
            if self.current_filter.lower() in packet.summary().lower():
                self.filtered_packets.append(http_request)
                if self.ui:
                    self.ui.add_packet_to_tree(self.index, http_request)
                    self.index += 1  # Increment the index
        elif packet.haslayer("TLS"):
            https_packet = HttpsPacket(packet)
            self.all_packets.append(https_packet)
            if self.current_filter.lower() in packet.summary().lower():
                self.filtered_packets.append(https_packet)
                if self.ui:
                    self.ui.add_packet_to_tree(self.index, https_packet)
                    self.index += 1  # Increment the index
        else:
            self.all_packets.append(packet)
            if self.current_filter.lower() in packet.summary().lower():
                self.filtered_packets.append(packet)

    def apply_filter(self, filter_text):
        self.current_filter = filter_text
        self.filtered_packets = [
            packet
            for packet in self.all_packets
            if self.current_filter.lower() in packet.summary().lower()
        ]
        return self.filtered_packets

    def start_sniffing(self):
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=False)
