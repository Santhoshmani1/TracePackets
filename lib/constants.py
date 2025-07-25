from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.all import packet

def get_layer(packet : packet) -> str:
    
    if packet.haslayer(HTTPRequest or HTTPResponse):
        print(packet.summary())
        return "HTTP" 
    elif packet.haslayer("HTTPS"):
        return "HTTPS"
    return "UNKNOWN"
