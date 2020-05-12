from protocol_analysis import run
from Source.protocol_analysis.extract_all_protocols import get_all_protocols

# need to change every time
# google files
from scapy.layers.dns import *
from scapy.layers.inet import *
from scapy import *
from scapy.layers import *
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import *
from scapy.layers.ntp import NTP
from scapy.utils import rdpcap

# file_list = ["/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_13.49.15_192.168.110.16.pcap",
#              "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_16.43.49_192.168.110.16.pcap",
#              "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_17.33.55_192.168.110.16.pcap"]
# device_ip = '192.168.110.16'

# amazon files
file_list = ["/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_09.41.57_192.168.110.14.pcap",
             "/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_10.10.11_192.168.110.14.pcap"]
device_ip = '192.168.110.14'

if __name__ == "__main__":
    all_pak = []
    for file_name in file_list:
        all_pak.extend(rdpcap(file_name))
    get_all_protocols(all_pak, device_ip)
