
# You must run as root or sudo in order to use this library 
# (it uses scapy, which requires root privileges to access low
# level socket functionality)

import json
from scapy.all import *

# The typical parameters for all of these functions
# are things like the number of EPs, the identifiers
# for the EPs, etc.  One question is where this data
# comes from. It likely comes from a configuration 
# file.

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

BROADCAST_MAC="ff:ff:ff:ff:ff:ff"
EP_IFACE_NAME='interface-name'
EP_MAC='mac'
EP_IP='ip'

class Ep:
    '''Class to keep endpoint state.'''
    def __init__(self, ip, mac):
        self.ip=ip
        self.mac=mac

    def set_ip(self, ip):
        self.ip=ip

    def set_mac(self, mac):
        self.mac=mac

    def get_mac(self, mac):
        return self.mac

    def get_ip(self, ip):
        return self.ip

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
        self.config={EP_DB_NAME: [], CONFIG_SOURCE: CONFIG_SOURCE_FILE }
        self.cfg_file_name = DEFAULT_CFG_FILE_NAME
        self.cfg_file = None

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
    


# The following are methods that are just wrappers around scapy
# calls, which provide the ability to send/receive packets using
# endpoints as identifiers.  They aren't useful yet, and are just
# placeholders for promised functionality (i.e. don't read too 
# much into the scapy calls that are there -- just put them 
# so that I could remember some of the useful calls).
def send_arp_request(ep1, ep2):
    '''Send an ARP request from EP1, trying
       to resolve the IP for EP2'''
    sendp(Ether(dst=BROADCAST_MAC)/
           ARP(pdst=ep2.get(EP_IP)[0], psrc=ep1.get(EP_IP)[0]),
                 iface=ep1.get(EP_IFACE_NAME))

def wait_arp_request(ep1, ep2, timeout=DEFAULT_TIMEOUT):
    '''Wait for an ARP request from EP1 on EP2'''
    opts=[]
    opts.append(SNIFF_FILTER + "='arp'")
    opts.append(SNIFF_TIMEOUT + "=" + str(timeout))
    opts.append(SNIFF_IFACE + "='" + ep2.get(EP_IFACE_NAME) + "'")

    pkts=wait_packet(opts)
    for pkt in pkts:
        if (ARP in pkt and pkt[ARP].op == 1 and
            pkt['Ethernet'].dst == BROADCAST_MAC and
            pkt[ARP].psrc == ep1.get(EP_IP)[0] and
            pkt[ARP].pdst == ep2.get(EP_IP)[0]):
            print "Received ARP Req from EP1 to EP2"

def send_arp_request_wait(ep1, ep2, timeout=DEFAULT_TIMEOUT):
    '''Send an ARP request from EP1, trying
       to resolve the IP for EP2, and wait
       for the response.'''
    ans,unans=srp1(Ether(dst=BROADCAST_MAC)/
        ARP(pdst=ep2.get(EP_IP)),timeout,iface=ep1.get(EP_IFACE_NAME))
    if ans == null:
        print "No response to ARP"
    else:
        ans.summary(lambda (s,r): r.sprintf("IP %ARP.psrc% has MAC %Ether.src%"))


def send_arp_response(ep1, ep2):
    '''Send an ARP response to EP2 from EP1,
       providing EP1's ARP resolution'''
    sendp(Ether(src=ep2.get(EP_MAC),dst=ep1.get(EP_MAC))/ARP(op="is-at", 
          psrc=ep2.get(EP_IP), pdst=ep1.get(EP_IP)))

def send_icmp_request(ep1, ep2):
    '''Send a ping request from EP1 to EP2, but
       don't wait for the response'''
    sendp(Ether(src=ep1.get(EP_MAC),dst=ep2.get(EP_MAC))/
            IP(src=ep1.get(EP_IP)[0], dst=ep2.get(EP_IP)[0])/ICMP(), iface=ep1.get(EP_IFACE_NAME))

def wait_icmp_request(ep1, ep2, timeout=DEFAULT_TIMEOUT):
    '''Wait for an ICMP echo request from EP1 on EP2'''
    opts=[]
    opts.append(SNIFF_FILTER + "='icmp'")
    opts.append(SNIFF_TIMEOUT + "=" + str(timeout))
    opts.append(SNIFF_IFACE + "='" + ep2.get(EP_IFACE_NAME) + "'")

    pkts=wait_packet(opts)
    for pkt in pkts:
        if (ICMP in pkt and pkt['ICMP'].type == 8 and
            pkt['Ethernet'].dst == ep2.get(EP_MAC) and
            pkt['IP'].src == ep1.get(EP_IP)[0] and
            pkt['IP'].dst == ep2.get(EP_IP)[0]):
            print "Received ICMP echo request from EP1 to EP2"

def send_icmp_wait(ep1, ep2):
    '''Send a ping request from EP1 to EP2, and
       wait for the response'''
    ans,unans=sr(IP(dst=ep2.get(EP_IP))/ICMP())

def send_tcp_data(ep1, ep2, dport, data):
    '''Send a TCP packet from EP1 to EP2 with the specified data,
       using the specified TCP destination port.'''
    sendp(Ether(src=ep1.get(EP_MAC),dst=ep2.get(EP_MAC))/
            IP(src=ep1.get(EP_IP)[0], dst=ep2.get(EP_IP)[0])/
            TCP(dport=dport), iface=ep1.get(EP_IFACE_NAME))

def wait_tcp_data(ep1, ep2, dport, data, timeout=DEFAULT_TIMEOUT):
    '''Wait for a TCP packet on the specified port from EP1 to EP2
       with the specified data'''
    opts=[]
    opts.append(SNIFF_FILTER + "='tcp'")
    opts.append(SNIFF_TIMEOUT + "=" + str(timeout))
    opts.append(SNIFF_IFACE + "='" + ep2.get(EP_IFACE_NAME) + "'")

    pkts=wait_packet(opts)
    for pkt in pkts:
        if (TCP in pkt and pkt['TCP'].dport == dport and
            pkt['Ethernet'].dst == ep2.get(EP_MAC) and
            pkt['IP'].src == ep1.get(EP_IP)[0] and
            pkt['IP'].dst == ep2.get(EP_IP)[0]):

            # TODO: verify the data is in the packet
            print "Received TCP packet from EP1 to EP2"

def send_multicast_data(ep1, ep2):
    '''Send a multicast packet from EP1 to
       the multicast group subscribed by EP2'''

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
