#!/usr/bin/env python
# Author Dario Clavijo 2019
# GPLv3

import socket
import struct
import ssl
import sys
import urllib.request, urllib.error, urllib.parse

UDP_IP = "127.0.0.1"
UDP_PORT = 53

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

hostname = sys.argv[1]
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

def sslget(url):
    req = urllib.request.Request(url)
    return urllib.request.urlopen(req, context=gcontext).read()

urlbase = "https://%s/dns-query?dns=" % hostname 

###print ssock
print("Proxy running...")

def DNS_dissect(data,addr):
	ID = data[0:2].encode('hex')
	QR = data[2:4].encode('hex')
	QD = data[4:6].encode('hex')
	AN = data[6:8].encode('hex')
	NS = data[8:10].encode('hex')
	AR = data[10:12].encode('hex')
	payload = data[12:].encode('hex')
	print("ADDR,ID,QR,QD,AN,NS,AR,payload")
	print(addr,ID,QR,QD,AN,NS,AR,payload)

while True:    
	data1, addr1 = sock.recvfrom(2048) # buffer size is 1024 bytes
        print("Client request")
	if len(data1) > 0:
		DNS_dissect(data1,addr1)
                url = urlbase + data1.encode("base64").replace("\n","").replace("\r","").replace("=","") 
                print(url)
                reply = sslget(url)
                print("Server reply")
                DNS_dissect(reply,(hostname,443))
                sock.sendto(reply,addr1)            
