class Search:
    def __init__(self, ui):
        self.ui = ui

    def apply_filter(self, filter_text):
        if not filter_text.strip():
            self.ui.update_tree(self.ui.packet_handler.all_packets)
            return

        filter_text = filter_text.lower()
        filtered_packets = [
            packet
            for packet in self.ui.packet_handler.all_packets
            if filter_text in packet.summary().lower()
        ]
        self.ui.update_tree(filtered_packets)
