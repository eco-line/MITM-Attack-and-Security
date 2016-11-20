from scapy.all import *
pkts = rdpcap('capture2.pcap')
#these are from wireshark
ipadr=['192.168.0.1','192.168.0.2','192.168.0.3','192.168.0.30']
macadr=['80:6c:1b:1f:83:bb','00:03:ff:98:98:02','64:5a:04:79:64:f7','00:03:ff:98:98:30']
c=-1
for p in pkts:
 c=c+1
 if p.haslayer(ARP):
  #find a packet where p.dst and p.pdst isn't a valid pair
  if p.dst != 'ff:ff:ff:ff:ff:ff':
   if not(( ipadr[0]==p.pdst and  macadr[0]==p.dst ) or ( ipadr[1]==p.pdst and macadr[1]==p.dst) or ( ipadr[2]==p.pdst and  macadr[2]==p.dst ) or ( ipadr[3]==p.pdst and  macadr[3]==p.dst )) :
		print 'packet data ' +p.psrc +"   "+p.src+"  " + p.pdst + " " + p.dst +" "+str(c)
		print 'packet number = ' + str(c)
		print 'MAC of attacker = ' + p.dst
		print 'IP of attacker = ' + ipadr[macadr.index(p.dst)]
		print 'MAC of target = ' + p.src
		print 'IP of target = ' + p.psrc