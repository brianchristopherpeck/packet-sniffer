#!usr/bin/env python

# Optperse allows options in cli
import optparse

# Scapy allows packet sniffing
try:
    import scapy.all as scapy
except ImportError:
    import scapy

# Scapy HTTP allows http packet support
try:
    # This import works from the project directory
    from scapy_http import http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

# Create command line arguments to be consumed by program
def c_args():
	# Calls the optparse package
	parser = optparse.OptionParser()
	# Sets allowable command line parameters and --help descriptions
	parser.add_option("-i", "--interface", dest="interface", help="Network Interface Card to sniff packets on")
	
	# Gather arguments and they're values (options)
	(options, _) = parser.parse_args()
	if not options.interface:
		parser.error("[-] Please specify an interface. Use --help for more info")
	return options

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

# Create the initiating arguments
options = c_args()

sniff(options.interface)