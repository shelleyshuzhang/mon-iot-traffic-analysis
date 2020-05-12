import copy
import csv
from datetime import datetime

from scapy.layers.inet import IP
from scapy.utils import rdpcap

from ..protocol_analysis.protocol_analysis import read_dst_csv

from ..protocol_analysis import Destination

# for google device
# file_name = 'experiment_2.csv'
# result_file_name = 'dst_time_google.csv'
# device_ip = '192.168.110.16'
# file_list = ["/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_13.49.15_192.168.110.16.pcap",
#              "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_16.43.49_192.168.110.16.pcap",
#              "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_17.33.55_192.168.110.16.pcap"]

# for amazon
file_name = 'experiment_1.csv'
result_file_name = 'dst_time_amazon.csv'
device_ip = '192.168.110.14'
file_list = ["/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_09.41.57_192.168.110.14.pcap",
             "/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_10.10.11_192.168.110.14.pcap"]


def run():
    packets = []
    for file in file_list:
        packets.extend(rdpcap(file))
    get_frequently_dst(packets=packets)


def get_frequently_dst(packets):
    hosts_info = read_dst_csv(file_name=file_name)

    with open(result_file_name, mode='w') as csv_file:
        fieldnames = ['host', 'ip', 'party', 'time']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for p in packets:
            epoch_time = p.time
            time = datetime.fromtimestamp(epoch_time)

            if p.haslayer(IP):
                p_copy = copy.deepcopy(p)
                current_ip = p_copy[IP].dst
                if current_ip != device_ip:
                    current: Destination = hosts_info[current_ip]
                    party = current.party
                    host = current.host
                    writer.writerow({'host': host,
                                     'ip': current_ip,
                                     'party': party,
                                     'time': time})
