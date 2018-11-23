
#449 Project
#Rotert/Jones

import dpkt, datetime
import socket, random

#Get filename, read packet with dpkt
file = open('tcpconnect.pcap', 'rb')
pcap = dpkt.pcap.Reader(file)

tcpconnect_srcips = []
xmas_srcips = []
null_srcips = []
udp_srcips = []
halfopen_srcips = []
suspiciousSrcIPs = []

for ts, buf in pcap:

	#Variables for reference:
	#---------------------------
	#srcip = Source IP Address
	#dstip = Destination IP Address
	#sport = Source Ports
	#dport = Destination Ports
	#type = frame type
	#---------------------------
	#TCP Flag Variables: 
	#fin_flag 
	#rst_flag
	#psh_flag
	#ack_flag
	#urg_flag
	#ece_flag
	#cwr_flag
	
	#Get Timestamp
	eth = dpkt.ethernet.Ethernet(buf)
	time = str(datetime.datetime.fromtimestamp(ts))
	
	if isinstance(eth.data, dpkt.icmp.ICMP):
		
		#Parse ICMP data
		icmp = eth.data
		typex = 'ICMP'
		
		#Source/Dest Addr/Ports
		srcip = icmp.src
		dstip = icmp.dst
		sport = icmp.sport
		dport = icmp.dport
	elif isinstance(eth.data, dpkt.ip.IP):
		ip = eth.data
		#IPs
		srcip = socket.inet_ntoa(ip.src)
		dstip = socket.inet_ntoa(ip.dst)
		#Check for UDP or TCP
		#UDP
		if type(ip.data) == 'UDP' :
			typex = 'IP, UDP'
			udp = ip.data
			sport = udp.sport
			dport = tcp.dport
		#TCP
		elif type(ip.data) == 'TCP' :
			typex = 'IP, TCP'
			tcp = ip.data
			sport = tcp.sport
			dport = tcp.dport
			
			#Check TCP Flags
			fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
			syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
			rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
			psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH ) != 0
			ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
			urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
			ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
			cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
		
	elif isinstance(eth.data, dpkt.arp.ARP) :
		arp = eth.arp
		typex = 'ARP'
		#Source/Dest IP/Ports
		srcip = socket.inet_ntoa(arp.spa)
		dstip = socket.inet_ntoa(arp.tpa)
		sport = 'N/A'
		dport = 'N/A'

	elif isinstance(eth.data, dpkt.ip6.IP6):
		ip6 = eth.data
		srcip = socket.inet_ntoa(ip6.src)
		dstip = socket.inet_ntoa(ip6.dst)
		
		#Check for TCP or UDP
		#UDP
		if type(ip6.data) == 'UDP' :
			typex = 'IPv6, UDP'
			udp = ip6.data
			sport = udp.sport
			dport = tcp.dport
		#TCP
		elif type(ip6.data) == 'TCP' :
			typex = 'IPv6, TCP'
			tcp = ip6.data
			sport = tcp.sport
			dport = tcp.dport
			
			#Check TCP Flags
			fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
			syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
			rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
			psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH ) != 0
			ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
			urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
			ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
			cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
			
			#Algorithm for TCP Connect Scan Detection
			#-------------------------------------------------------------
			#SYN -> SYN_ACK -> ACK -> RST_ACK  OR SYN-> RST_ACK
			#If an IP address sends a SYN packet, add to list of suspicious IPs
			#If an IP address responds a RST,ACK where the destination IP is the name as the source as before, then we probably have a TCP connect port scan
			#Add the IP address to the tcpconnect_srcips list
			#LEN of tcpconnect_srcips list is the # of port scans - we could use this to compile a list of ipaddresses scanned by the suspicious IP? but i dont think we need to do that @emily 
			
			#SYN Packet - XOR all flags to protect from false detections
			if (syn_flag ^ fin_flag ^ rst_flag ^ psh_flag ^ ack_flag ^ urg_flag ^ ece_flag ^ cwr_flag) :
				if (suspiciousSrcIPs.contains(srcip)) :
					i = suspiciousSrcIPs.locationof(srcip)
					
					continue
				else :
					suspiciousSrcIPs.add(srcip)
					susIPc.add(1)
					
			#RST_ACK - AND Reset and Ack flags
			if (rst_flag && ack_flag) :
				if (suspiciousSrcIPs.contains(dstip) && !tcpconnect_srcips.contains(dstip))
					tcpconnect_srcips.add(dstip)
					continue
				
			
			
					
					
				
	else :
		#Not an ethernet frame so we dont care i think
		print(' not ethernet frame ')
		continue		
	#Output for debug

	print('Timestamp : ', time)
	print('Type : ', typex)
	print('Source IP : ', srcip)
	print('Dest IP : ', dstip)
	print('Source Port : ' , sport)
	print('Destination Port : ', dport)
	print ('\n\n')
	



	
	
	
	




