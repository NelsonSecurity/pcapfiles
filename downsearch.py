import argparse
import re
from scapy.all import *
from scapy_http import http


def process_packet(pcap):
	if pcap.haslayer(http.HTTPRequest):
		http_layer = pcap.getlayer(http.HTTPRequest)
		ip_layer = pcap.getlayer(IP)
		method = '{0[Method]}'.format(http_layer.fields)
		host = '{0[Host]}'.format(http_layer.fields)
		payload = pcap[TCP].payload
		payload = str(payload)
		payload_email = payload.find('MZ')
	
		if method.startswith('GET') and payload_email and not host.startswith('ocsp.') and not host.startswith('pki.treasury.gov') and not host.startswith('http.fpki.gov') and not host.startswith('clienttemplates.content.office.net'):
			print('{0[src]} {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields))

	if pcap.haslayer(http.HTTPResponse):
		http_response = pcap.getlayer(http.HTTPResponse)
		ip_layer = pcap.getlayer(IP)
		payload = pcap[TCP].payload
		payload = str(payload)
		payload_email = re.findall(r'MZ(.*)', str(payload))
		download = re.findall(r'attachment;(.*)', str(http_response))
		
		if download:
			print(download)
			print(payload_email)
	return


	

parser = argparse.ArgumentParser(description="PCAP Parser")
parser.add_argument('-p', "--pcap", help="PCAP file")
args = parser.parse_args()

PCAP_file = args.pcap

try:
	packet = rdpcap(PCAP_file)
except:
	print("Invalid PCAP File")

try:
	for pkt in packet:
		process_packet(pkt)

except:
	print("Error Processing PCAP")
