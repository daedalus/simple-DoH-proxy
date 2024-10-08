#!/usr/bin/env python
# Author Dario Clavijo 2019
# GPLv3

import socket
import struct
import ssl
import sys
import base64
import urllib.request, urllib.error, urllib.parse

UDP_IP = "127.0.0.1"
UDP_PORT = 53
hostname = "1.1.1.1"
urlbase = f"https://{hostname}/dns-query?dns=" 

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))
hostname = sys.argv[1]
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)


def sslget(url):
	req = urllib.request.Request(url)
	return urllib.request.urlopen(req, context=gcontext).read()


def DNS_dissect(data, addr):
	ID = data[:2].hex()
	QR = data[2:4].hex()
	QD = data[4:6].hex()
	AN = data[6:8].hex()
	NS = data[8:10].hex()
	AR = data[10:12].hex()
	payload = data[12:].hex()
	print(f"ADDR: {addr}, ID: {ID}, QR: [QR], QD: {QD}, AN: {AN}, NS: {NS}, AR: {AR}, payload: {payload}")


def main():
	print("Proxy running...")
	while True:    
		try:
			data1, addr1 = sock.recvfrom(2048) # buffer size is 1024 bytes
			print("Client request")
			if len(data1) > 0:
				DNS_dissect(data1, addr1)
				url = urlbase + base64.b64encode(data1).replace(b"\n",b"").replace(b"\r",b"").replace(b"=",b"").decode() 
				print(url)
				reply = sslget(url)
				print("Server reply")
				DNS_dissect(reply,(hostname,443))
				sock.sendto(reply,addr1)            
		except:
			pass

if __name__ == "__main__":
	main()
