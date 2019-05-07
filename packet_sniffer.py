#!usr/bin/env python

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    from scapy_http import http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

def sniff(interface):
    # interface, the interface being sniffed, store, whether to store packets in memory (takes toll on cpu),
    # prn, allows for a callback function
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("/----------------------------/")
        print("---------BEGIN PACKET--------/")
        print(packet.show())
        print("----------END PACKET---------/")
        print("/----------------------------/")

sniff("en0")