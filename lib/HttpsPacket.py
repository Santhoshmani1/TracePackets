from lib.HttpPacket import HttpPacket
from scapy.layers.inet import IP
from scapy.layers.tls.all import TLS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.all import Raw

class HttpsPacket(HttpPacket):
    def __init__(self, packet):
        super().__init__(packet)
        if IP in packet:
            self.src = packet[IP].src
            self.dst = packet[IP].dst
        else:
            self.src = "Unknown"
            self.dst = "Unknown"
        self.proto = "HTTPS"
        self.info = packet.summary()

        if packet.haslayer(HTTPRequest):
            self.method = packet[HTTPRequest].Method.decode()
            self.host = packet[HTTPRequest].Host.decode()
            self.path = packet[HTTPRequest].Path.decode()
            self.user_agent = (
                packet[HTTPRequest].User_Agent.decode()
                if "User_Agent" in packet[HTTPRequest].fields
                else ""
            )
            self.referer = (
                packet[HTTPRequest].Referer.decode()
                if "Referer" in packet[HTTPRequest].fields
                else ""
            )
            self.cookie = (
                packet[HTTPRequest].Cookie.decode()
                if "Cookie" in packet[HTTPRequest].fields
                else ""
            )
            self.content_type = (
                packet[HTTPRequest].Content_Type.decode()
                if "Content_Type" in packet[HTTPRequest].fields
                else ""
            )
            self.content_length = (
                packet[HTTPRequest].Content_Length.decode()
                if "Content_Length" in packet[HTTPRequest].fields
                else ""
            )
        elif packet.haslayer(HTTPResponse):
            self.response_code = packet[HTTPResponse].Status_Code.decode()
            self.response_phrase = packet[HTTPResponse].Reason_Phrase.decode()
            self.response_length = len(packet[HTTPResponse])
            self.response_content_type = (
                packet[HTTPResponse].Content_Type.decode()
                if "Content_Type" in packet[HTTPResponse].fields
                else ""
            )
            self.response_content_length = (
                packet[HTTPResponse].Content_Length.decode()
                if "Content_Length" in packet[HTTPResponse].fields
                else ""
            )
            self.response_body = (
                packet[Raw].load.decode(errors="ignore") if Raw in packet else ""
            )

    def get_tls_details(self):
        if TLS in self.packet:
            return self.packet[TLS].show(dump=True)
        return "No TLS details available"