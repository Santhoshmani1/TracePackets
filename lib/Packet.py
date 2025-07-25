from scapy.all import Raw


class Packet:
    def __init__(self, packet):
        self.packet = packet

    def get_raw_payload(self):
        if Raw in self.packet:
            return self.packet[Raw].load
        return None

    def get_raw_payload_hex(self):
        raw_payload = self.get_raw_payload()
        if raw_payload:
            return raw_payload.hex()
        return None

    def get_raw_payload_plaintext(self):
        raw_payload = self.get_raw_payload()
        if raw_payload:
            return raw_payload.decode(errors="ignore")
        return None

    def summary(self):
        return self.packet.summary()

    def get_length(self):
        return len(self.packet)
