
# You must run as root or sudo in order to use this library 
# (it uses scapy, which requires root privileges to access low
# level socket functionality)

import json
from scapy.all import *
from multiprocessing import Process

BROADCAST_MAC="ff:ff:ff:ff:ff:ff"

CONFIG_SOURCE='source'
CONFIG_SOURCE_FILE='file'
DEFAULT_CFG_FILE_NAME='endpoints.json'
EP_DB_NAME='ep-db'

SNIFF_FILTER='filter'
SNIFF_TIMEOUT='timeout'
SNIFF_COUNT='count'
SNIFF_STORE='store'
SNIFF_IFACE='iface'

DEFAULT_TIMEOUT=10


OS_EP_IFACE_NAME='interface-name'
OS_EP_MAC='mac'
OS_EP_IP='ip'
OS_EP_POLICY='policy-space'
OS_EP_EPG='endpoint-group'
OS_EP_UUID='uuid'

ODL_EP_MAC='mac-address'
ODL_EP_MAC='ip-address'

ODL_EP_TYPE='OpenDaylight'
OS_EP_TYPE='OpenStack'

#
#  This is sample python code for how this module could
#  be used:
#
#  <on both VMs>:
#
#     from trafficgen import *
#
#     x=TestConfig()
#     x.get_configuration()
#     x.create_ep_db()
#     ep1 = x.epdb[0]
#     ep2 = x.epdb[1]
#
# <on VM #1>
#     wait_tcp_data(ep1, ep2, 80, 'foobar-t-robot', timeout=5)
# <on VM #2>
#     send_tcp_data(ep1, ep2, 80, 'foobar-t-robot')
#
#  You can also create a list of processes to execute, so that you
#  can send and receive at the same time.  As an example:
#
#     plist=[(wait_tcp_data,(ep1, ep2, 80, 'foobar-t-robot', 5)),(send_tcp_data,(ep1, ep2, 80, 'foobar-t-robot'))]
#     pidlist=create_multi(plist)
#     for pid in pidlist:
#         pid.start()
#
class Ep:
    '''Class to keep endpoint state. It provides a normalized 
       interface, regardless of the underlying type of endpoint 
       (OpenDaylight, OpenStack, etc.).'''
    def __init__(self, ep_type, ep):
        if ep_type == ODL_EP_TYPE:
            print ODL_EP_TYPE + " is not yet supported"
        elif ep_type == OS_EP_TYPE:
            if ep.get(OS_EP_MAC) != None:
                self.mac=ep.get(OS_EP_MAC)
            if ep.get(OS_EP_IP) != None:
                self.ip=ep.get(OS_EP_IP)[0]
            if ep.get(OS_EP_IFACE_NAME) != None:
                self.interface=ep.get(OS_EP_IFACE_NAME)
            if ep.get(OS_EP_POLICY) != None:
                self.policy=ep.get(OS_EP_POLICY)
            if ep.get(OS_EP_EPG) != None:
                self.epg=ep.get(OS_EP_EPG)
            if ep.get(OS_EP_UUID) != None:
                self.uuid=ep.get(OS_EP_UUID)

    def set_mac(self, mac):
        self.mac=mac

    def get_mac(self):
        return self.mac

    def set_ip(self, ip):
        self.ip=ip

    def get_ip(self):
        return self.ip

    def set_interface(self, interface):
        self.interface = interface

    def get_interface(self):
        return self.interface

    def set_policy(self, policy):
        self.policy = policy

    def get_policy(self):
        return self.policy

    def set_epg(self, epg):
        self.epg = epg

    def get_epg(self):
        return self.epg

class TestConfig:
    '''The TestConfig class is what keeps the configuration needed
       to run a given test. Initially, this just acts as a database
       of endpoints that can be used for the test.  Endpoints can 
       take different forms, based on the consumer, so a dictionary
       is used to keep this information.  The current endpoint formats
       supported are OpenDaylight Group Based Policy OpenStack endpoints,
       Opflex agent endpoints, and OpenStack Group Based Policy endpoints.
       Other endpoint formats could easily be supported.

       OpenDaylgith GBP OpenStack Endpoint format:
       {
           "l2-context": "3c8b10db-1dbe-4108-84b7-ba48226b352e",
           "mac-address": "fa:16:3e:54:c9:cf",
           "neutron-port-id": "tap0979cab9-af",
           "timestamp": 1421190990899,
           "tenant": "a55d2062-450d-4cee-9a43-81dea8184a09",
           "endpoint-group": "7dfd8b0a-5933-4e14-997d-a7381073786e",
           "l3-address": [
               {
                   "l3-context": "eabbbe73-bfdb-4316-890d-d49ee96f4e48",
                   "ip-address": "10.0.0.4"
               }
           ]
       }
    
       OpFlex agent Endpoint format:
       {
           "policy-space": "test",
           "endpoint-group": "group1",
           "interface-name": "s1-eth1",
           "ip": [
               "10.0.0.1"
           ],
           "mac": "00:00:00:00:00:01",
           "uuid": "83f18f0b-80f7-46e2-b06c-4d9487b0c754"
       }
    
       OpenStack GBP Endpoint format: tbd'''

    def get_config_from_file(self):
        self.cfg_file = self.open_file(self.cfg_file_name)
        if self.cfg_file == None:
            print "Couldn't open file " + self.cfg_file
            exit(1)
        self.config[EP_DB_NAME]=json.load(self.cfg_file)

    def open_file(self, filename):
        if filename == '':
            print "file name not set"
            return None

        f = open(filename, "r");
        if f == None:
            print "Error opening file " + filename
            return None
        return f

    def __init__(self):
        '''Initialize the test configuration'''
        self.config = ({ EP_DB_NAME: [], 
                         CONFIG_SOURCE: CONFIG_SOURCE_FILE 
                       })
        self.cfg_file_name = DEFAULT_CFG_FILE_NAME
        self.cfg_file = None
        self.epdb = []

    def set_config_source(self, source):
        self.config[CONFIG_SOURCE] = source

    def get_configuration(self):
        '''Get the configuration used for testing.
           This includes things like the number of
           EPs, their identifiers, etc.'''
        new_config={}
        source = self.config.get(CONFIG_SOURCE)
        if source == None:
            print "No configuration source set, exiting"
            exit(1)
        if source == CONFIG_SOURCE_FILE:
            self.get_config_from_file()
    
    def create_ep_db(self):
        '''Creat the Ep objects from the JSON data'''
        if self.config != None:
            for ep in self.config[EP_DB_NAME]:
                e = self.config[EP_DB_NAME].get(ep)
                # Find out what type of EP we've got
                if ODL_EP_MAC in e:
                    self.epdb.append(Ep(ODL_EP_TYPE, e))
                elif OS_EP_MAC in e:
                    self.epdb.append(Ep(OS_EP_TYPE, e))


def get_std_opts(ep2, timeout, proto):
    opts=[]
    opts.append(SNIFF_TIMEOUT + "=" + str(timeout))
    opts.append(SNIFF_IFACE + "='" + ep2.get_interface() + "'")
    opts.append(SNIFF_FILTER + "='" + proto + "'")
    return opts

def verify_eth(pkt, ep1, ep2):
    if (pkt['Ethernet'].src == ep1.get_mac() and
        pkt['Ethernet'].dst == ep2.get_mac()):
        return True
    else:
        return False

def verify_arp(pkt, ep1, ep2):
    if (pkt[ARP].psrc == ep1.get_ip() and
        pkt[ARP].pdst == ep2.get_ip()):
        return True
    else:
        return False

def verify_ip(pkt, ep1, ep2):
    if (pkt[IP].src == ep1.get_ip() and
        pkt[IP].dst == ep2.get_ip()):
        return True
    else:
        return False

def verify_signature(pkt, signature):
    if signature == '':
        return True
    elif ('Raw' in pkt and signature in [pkt['Raw'].load]):
        return True
    return False


# The following are methods that are just wrappers around scapy
# calls, which provide the ability to send/receive packets using
# endpoints as identifiers.  These could be moved into the EPs,
# as then you'd only have to specify one of the EPs; however, 
# it may be just as easy to keep these as standalone functions
# since you'll be operating with sets of EPs anyway.
def send_arp_request(ep1, ep2):
    '''Send an ARP request from EP1, trying
       to resolve the IP for EP2'''
    sendp(Ether(dst=BROADCAST_MAC)/
          ARP(pdst=ep2.get_ip(), psrc=ep1.get_ip()),
          iface=ep1.get_interface())

def wait_arp_request(ep1, ep2, timeout=DEFAULT_TIMEOUT):
    '''Wait for an ARP request from EP1 on EP2'''
    opts=get_std_opts(ep2, timeout, 'arp')
    pkts=wait_packet(opts)
    for pkt in pkts:
        if (ARP in pkt and pkt[ARP].op == 1 and
            pkt['Ethernet'].dst == BROADCAST_MAC and
            verify_arp(pkt, ep1, ep2)):
            print "Received ARP Req from EP1 to EP2"

#def send_arp_request_wait(ep1, ep2, timeout=DEFAULT_TIMEOUT):
#    '''Send an ARP request from EP1, trying
#       to resolve the IP for EP2, and wait
#       for the response.'''
#    ans,unans=srp1(Ether(dst=BROADCAST_MAC)/
#        ARP(pdst=ep2.get_ip(), psrc=ep1.get_ip()),
#        iface=ep1.get_interface())
#    if ans == null:
#        print "No response to ARP"
#    else:
#        ans.summary(lambda (s,r): r.sprintf("IP %ARP.psrc% has MAC %Ether.src%"))


def send_arp_response(ep1, ep2):
    '''Send an ARP response to EP2 from EP1,
       providing EP1's ARP resolution'''
    sendp(Ether(src=ep2.get_mac(),dst=ep1.get_mac())/
          ARP(op="is-at", psrc=ep2.get_ip(), pdst=ep1.get_ip()))

def send_icmp_request(ep1, ep2, signature=''):
    '''Send a ping request from EP1 to EP2, but
       don't wait for the response'''
    sendp(Ether(src=ep1.get_mac(),dst=ep2.get_mac())/
          IP(src=ep1.get_ip(), dst=ep2.get_ip())/
          ICMP(), iface=ep1.get_interface())

def wait_icmp_request(ep1, ep2, signature='', timeout=DEFAULT_TIMEOUT):
    '''Wait for an ICMP echo request from EP1 on EP2'''
    opts=get_std_opts(ep2, timeout, 'icmp')
    pkts=wait_packet(opts)
    for pkt in pkts:
        if (ICMP in pkt and pkt['ICMP'].type == 8 and
            verify_eth(pkt, ep1, ep2) and
            verify_ip(pkt, ep1, ep2) and
            verify_signature(pkt, signature)):
            print "Received ICMP echo request from EP1 to EP2"

#def send_icmp_wait(ep1, ep2):
#    '''Send a ping request from EP1 to EP2, and
#       wait for the response'''
#    ans,unans=sr(IP(dst=ep2.get_ip())/ICMP())

def send_tcp_data(ep1, ep2, dport, signature=''):
    '''Send a TCP packet from EP1 to EP2 with the specified signature,
       using the specified TCP destination port.'''
    sendp(Ether(src=ep1.get_mac(),dst=ep2.get_mac())/
          IP(src=ep1.get_ip(), dst=ep2.get_ip())/
          TCP(dport=dport)/
          Raw(load=signature), iface=ep1.get_interface())

def wait_tcp_data(ep1, ep2, dport, signature='', timeout=DEFAULT_TIMEOUT):
    '''Wait for a TCP packet on the specified port from EP1 to EP2
       with the specified signature'''
    opts=get_std_opts(ep2, timeout, 'tcp')
    pkts=wait_packet(opts)
    for pkt in pkts:
        if (TCP in pkt and pkt['TCP'].dport == dport and
            verify_eth(pkt, ep1, ep2) and
            verify_ip(pkt, ep1, ep2) and
            verify_signature(pkt, signature)):
            print "Received TCP packet from EP1 to EP2"

def send_udp_data(ep1, ep2, dport, signature=''):
    '''Send a UDP packet from EP1 to EP2 with the specified signature,
       using the specified UDP destination port.'''
    sendp(Ether(src=ep1.get_mac(),dst=ep2.get_mac())/
            IP(src=ep1.get_ip(), dst=ep2.get_ip())/
            UDP(dport=dport)/
            Raw(load=signature), iface=ep1.get_interface())

def wait_udp_data(ep1, ep2, dport, signature='', timeout=DEFAULT_TIMEOUT):
    '''Wait for a UDP packet on the specified port from EP1 to EP2
       with the specified signature'''
    opts=get_std_opts(ep2, timeout, 'udp')
    pkts=wait_packet(opts)
    for pkt in pkts:
        if (UDP in pkt and pkt['UDP'].dport == dport and
            verify_eth(pkt, ep1, ep2) and
            verify_ip(pkt, ep1, ep2) and
            verify_signature(pkt, signature)):
            print "Received UDP packet from EP1 to EP2"

def send_multicast_data(ep1, mcast_ip):
    '''Send a multicast packet from EP1 to
       the multicast group subscribed by EP2'''
    sendp(Ether(src=ep1.get(EP_MAC))/
          IP(src=ep1.get_ip(), dst=mcast_ip)/
          UDP(), iface=ep1.get_interface())

def wait_packet(packetarray):
    '''Wait for any packet on a given endpoint.
       The packet that we're waiting for is defined
       by the packetarray array.  The packetarray
       allows specifying the parameters used to define
       the traffic that is waited for. The following are
       the parameters supported in the array:

          count: number of packets to capture. 0 means infinity
          store: wether to store sniffed packets or discard them
            prn: function to apply to each packet. If something is returned,
                 it is displayed. Ex:
                 ex: prn = lambda x: x.summary()
         filter: python function applied to each packet to determine
                 if further action may be done
                 ex: lfilter = lambda x: x.haslayer(Padding)
        offline: pcap file to read packets from, instead of sniffing them
        timeout: stop sniffing after a given time (default: None)
        L2socket: use the provided L2socket
        opened_socket: provide an object ready to use .recv() on
        stop_filter: python function applied to each packet to determine
                     if we have to stop the capture after this packet
                     ex: stop_filter = lambda x: x.haslayer(TCP)
       '''
    optstring=''
    for opt in packetarray:
        optstring += opt + ','
    pkts=eval("sniff(" + optstring[:-1] + ")")
    return pkts

def create_multi(plist):
    '''Create a process per item in the list
       Items in the list should be tuples, where
       the first item in the tuple is a function
       and the second item in the tuple is another
       tuple for the arguments to that function.
       The process objects are returned as a list.'''
    pids=[]
    # create list of process objects
    for p in plist:
        f,args = p
        pid = Process(target=f, args=args)
        pids.append(pid)

    return pids
