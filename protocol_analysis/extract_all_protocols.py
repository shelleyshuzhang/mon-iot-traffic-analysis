import copy
from scapy.layers.inet import *
from scapy.utils import rdpcap

# google files
file_list = ["/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_13.49.15_192.168.110.16.pcap",
             "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_16.43.49_192.168.110.16.pcap",
             "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_17.33.55_192.168.110.16.pcap"]
device_ip = '192.168.110.16'


# amazon files
# file_list = ["/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_09.41.57_192.168.110.14.pcap",
#              "/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_10.10.11_192.168.110.14.pcap"]

# get all the protocols in a list of pcap
# files and write them to a txt file
def run_ext_protocols():
    all_pak = []
    for file_name in file_list:
        all_pak.extend(rdpcap(file_name))
    get_all_protocols(all_pak, device_ip)


# get all the protocols and corresponding packets
# as a lot of pairs (protocol name -> packet)
def get_all_protocols(packets: list, device_ip_address):
    protocol_file = open('protocol_used.txt', 'w+')
    all_protocols = {"RECEIVED:": set(), "SENT:": set()}
    for p in packets:
        p_copy = copy.deepcopy(p)
        if p_copy.haslayer(IP):

            # get the protocol info
            protocol = p_copy.lastlayer().name
            if protocol == "Raw":
                pros = list(p_copy.iterpayloads())
                protocol = pros[pros.__len__() - 2].name
            if not protocol.startswith("IP"):
                protocol = protocol.split()[0]
            else:
                protocol = "IGMPv3"

            pak_ip = p_copy[IP].src
            if device_ip_address == pak_ip:
                if p.haslayer(UDP) or p.haslayer(TCP):
                    port_dst = " port: " + str(p.dport)
                else:
                    port_dst = ""
                all_protocols["SENT:"].add(protocol + port_dst)
            else:
                if p.haslayer(UDP) or p.haslayer(TCP):
                    port_src = " port: " + str(p.sport)
                else:
                    port_src = ""
                all_protocols["RECEIVED:"].add(protocol + port_src)
    for pak_group in all_protocols:
        protocol_file.write(pak_group + '\n')
        for pro in all_protocols[pak_group]:
            protocol_file.write(pro + '\n')
    protocol_file.close()
