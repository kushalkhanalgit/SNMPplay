
#!/bin/python

"""
PySNMP hides all the complexity of snmp processing behind a single class with simple API.All you have to do is create an instance of ...
CommandGenerator class. The class is available from pysnmp.entity.rfc3413.oneliner.cmdgen module and implements standard snmp command...    
like  getCmd(),setCmd(),nextCmd()
"""

from pysnmp.entity.rfc3413.oneliner import cmdgen
import sys

cg = cmdgen.CommandGenerator()

# mpModel means default even if we don't indicate , its for snmpv2c version.
community_data = cmdgen.CommunityData('security_string', 'public', mpModel = 0)

# agent_IP can be IP of fully qualified domain name. This input is taken from user.
transport = cmdgen.UdpTransportTarget(('agent_IP', 161))

#each number in OID represents node ID of MIB tree and each has meaning;
#have created a tuple of all node IDs, that makes up OID we are querying; dot-separated to comma-separated
snmpOIDs = (1,3,6,1,2,1,1,1,0)

"""
#the output of below command is a tuple w/ four value errIndication, errStatus, errIndex, result, where...
#i)errIndication non-empty means there is engine error ; None for error free
#ii)errStatus goes True for error ; 0 if snmp queried successfully
#iii)errIndex gives exact index what got errored; 0 if snmp query is success
#iv)result is a tuple with OID and corresponding value
/#getCmd is API command to implement SNMP GET, which is pushed the three input arguments
"""

errIndication, errStatus, errIndex, result = cg.getCmd(community_data, transport, snmpOIDs)


"""
OUTPUT sample for 'result' if query is success :
[(None, 0, 0, ObjectName('1.3.6.1.2.3.4.1.0'), OctetString('Linux fedolin.example.com 2.6.32.11-99.fc12.i686 #1 SMP Mon Apr 5 16:32:08 EDT 2010 i686'))]
"""
 

################DISCOVER IP FROM POOL USING SCAPY (or alternatively use nmap , like nmap -sn ip_pool/length########################

from scapy.all import ARP, Ether, srp


#Example we got "192.168.1.1/24"
# IP Addresses for the destination
target_ip = input("Enter target ip pool in format x.x.x.x/xx")

# create ARP packet
dst_arp = ARP(pdst=target_ip)

# create the Ether broadcast packet
# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
dst_ether = Ether(dst="ff:ff:ff:ff:ff:ff")

# stack them
packet_created = dst_ether/dst_arp

#Now we have created these packets, we need to send them using srp() function which sends and receives packets at layer 2,...
#we set the timeout to #3 so the script won't get stuck

result = srp(packet_created, timeout=3, verbose=0)[0]

# Initalize a list, to populate clients that will reply from the pool supplied by user
clients = []

for sent, received in result:
	# for each response, append ip and mac address to `clients` list
	clients.append({'ip': received.psrc, 'mac': received.hwsrc})

# print clients
print("Available devices in the network:")
print("IP" + " "*18+"MAC")
for client in clients:
	print("{:16}	{}".format(client['ip'], client['mac']))
