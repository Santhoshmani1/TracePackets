from lib.Packet import Packet
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.all import Raw


class HttpPacket(Packet):
    def __init__(self, packet):
        super().__init__(packet)
        if IP in packet:
            self.src = packet[IP].src
            self.dst = packet[IP].dst
        else:
            self.src = "Unknown"
            self.dst = "Unknown"
        self.proto = "HTTP"
        self.method = ""
        self.host = ""
        self.path = ""
        self.user_agent = ""
        self.referer = ""
        self.cookie = ""
        self.content_type = ""
        self.content_length = ""
        self.response_code = ""
        self.response_phrase = ""
        self.response_length = ""
        self.response_content_type = ""
        self.response_content_length = ""
        self.response_body = ""

        if packet.haslayer(HTTPRequest):
            """Extract HTTP request information."""
            self.info = f"HTTP Request: {packet[HTTPRequest].Method.decode()} {packet[HTTPRequest].Host.decode()}{packet[HTTPRequest].Path.decode()}"
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
            """Extract HTTP response information."""
            self.info = f"HTTP Response: {packet[HTTPResponse].Status_Code.decode()} {packet[HTTPResponse].Reason_Phrase.decode()}"
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
        else:
            self.info = packet.summary()

    def get_request_headers(self):
        """Helper method to get the request headers."""
        headers = {
            "Method": self.method,
            "Host": self.host,
            "Path": self.path,
            "User-Agent": self.user_agent,
            "Referer": self.referer,
            "Cookie": self.cookie,
            "Content-Type": self.content_type,
            "Content-Length": self.content_length,
        }
        return {key: value for key, value in headers.items() if value}

    def get_response_headers(self):
        """Helper method to get the response headers."""
        headers = {
            "Status-Code": self.response_code,
            "Content-Type": self.response_content_type,
            "Content-Length": self.response_content_length,
            "Body": self.response_body,
            "Length": self.response_length,
        }
        return {key: value for key, value in headers.items() if value}
