###### be careful with deep/shallow copy ######

import copy
import csv

from scapy.utils import rdpcap

from Source.protocol_analysis.Destination import Destination
from Source.protocol_analysis.DestinationPro import DestinationPro
from Source.protocol_analysis.ProtocolPort import ProtocolPort

####### must import the packet in scapy in order to see the results #######
from scapy.layers.dns import *
from scapy.layers.inet import *
from scapy import *
from scapy.layers import *
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import *
from scapy.layers.ntp import NTP

options1 = ('device', 'ip', 'host', 'host_full', 'traffic_snd',
            'traffic_rcv', 'packet_snd', 'packet_rcv', 'country',
            'party', 'lab', 'experiment', 'network', 'input_file',
            'organisation')
options2 = ('ip', 'host', 'party', 'protocol&port',
            'encrypted', 'well-known', 'human-readable',
            'snd', 'rcv', 'importance')
party_name_dict = {"-1": "Non-internet", "0": "First party",
                   "1": "Support party", "2": "Advertisers",
                   "2.5": "Other third parties"}
protocol_known_dict = {"1": "well-known", "0": "unknown", "0.5": "registered"}
protocol_readable_dict = {"1": "human-readable", "0": "human-unreadable",
                          "0.5": "partially human-readable"}
protocol_encrypted_dict = {"1": "encrypted", "0.5": "partially encrypted",
                           "0": "unencrypted", "-1": "unknown"}
protocol_importance_dict = {"1": "important", "0": "unimportant"}
#######################
# need to change every time
# google files
# file_list = ["/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_13.49.15_192.168.110.16.pcap",
#              "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_16.43.49_192.168.110.16.pcap",
#              "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_17.33.55_192.168.110.16.pcap"]
# device_ip = '192.168.110.16'

# amazon files
file_list = ["/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_09.41.57_192.168.110.14.pcap",
             "/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_10.10.11_192.168.110.14.pcap"]
device_ip = '192.168.110.14'

dst_file = 'experiment_1.csv'
pro_file = './protocol_analysis/protocols_amazon_info.csv'
result_file_name = 'dst_pros_amazon.csv'


############################################


def run():
    all_pak = []
    for file_name in file_list:
        all_pak.extend(rdpcap(file_name))
    result = dst_protocol_analysis(all_pak, device_ip, dst_file, pro_file)
    with open(result_file_name, mode='w') as csv_file:
        fieldnames = ['ip', 'host', 'party', 'protocol&port',
                      'encrypted', 'well-known', 'human-readable',
                      'snd', 'rcv', 'importance']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for dp in result:
            dst = dp.host
            pro = dp.protocol_port
            send = dp.snd
            received = dp.rcv
            writer.writerow({'ip': dst.ip,
                             'host': dst.host,
                             'party': dst.party,
                             'protocol&port': pro.protocol_port,
                             'encrypted': pro.encrypted,
                             'well-known': pro.well_known,
                             'human-readable': pro.readable,
                             'snd': send,
                             'rcv': received,
                             'importance': pro.imp})
    csv_file.close()


def dst_protocol_analysis(packets, d_ip, destination_file, protocol_file):
    result = []
    dst_info: dict = read_dst_csv(destination_file)
    protocol_info: dict = read_protocol_csv(protocol_file)

    for p in packets:
        p_ip, snd_rcv = get_pak_ip(p, d_ip)
        if p_ip != 'non-ip' and p_ip in dst_info:
            p_protocol = get_pak_protocol(p, d_ip)
            current = DestinationPro(dst_info[p_ip],
                                     protocol_info[p_protocol])
            if current in result:
                index = result.index(current)
                if snd_rcv == 'snd':
                    result[index].add_snd(len(p))
                else:
                    result[index].add_rcv(len(p))
            else:
                if snd_rcv == 'snd':
                    current.add_snd(len(p))
                else:
                    current.add_rcv(len(p))
                result.append(current)
    return result


# For expected: 1 (well-known), 0 (unknown), 0.5 (potentially encrypted)
# For encrypted: 1 (encrypted), 0 (unencrypted), 0.5 (partially encrypted)
# return: dict (keys: Protocol&port, SENT:, RECEIVED:, Expected, Encrypted)
def read_protocol_csv(file_name):
    protocols_info = {}
    with open(file_name, mode='r', encoding='utf-8-sig') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            protocol = row["Protocol&port"]
            encrypted = row["Encrypted"]
            known = row["Well-known"]
            readable = row["Human-readable"]
            imp = row["Importance"]
            current = ProtocolPort(protocol_port=protocol,
                                   encrypted=encrypted,
                                   expected=known,
                                   readable=readable,
                                   importance=imp)
            protocols_info[protocol] = current
    csv_file.close()
    return protocols_info


# keys are option1
def read_dst_csv(file_name):
    hosts_info = {}
    with open(file_name, mode='r', encoding='utf-8-sig') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            host = row['host']
            party = row['party']
            ip = row['ip']
            current = Destination(host=host,
                                  party=party,
                                  ip=ip)
            hosts_info[ip] = current
    csv_file.close()
    return hosts_info


def get_pak_protocol(packet, d_ip):
    if packet.haslayer(IP):

        # get the protocol info
        pak_copy = copy.deepcopy(packet)
        protocol = pak_copy.lastlayer().name
        if protocol == "Raw":
            pros = list(pak_copy.iterpayloads())
            protocol = pros[pros.__len__() - 2].name
        if not protocol.startswith("IGMPv3mr"):
            protocol = protocol.split()[0]
        else:
            protocol = "IGMPv3"

        # get port number information
        port_number = ""
        pak_copy = copy.deepcopy(packet)
        pak_ip = pak_copy[IP].src
        if d_ip == pak_ip:
            if packet.haslayer(UDP) or packet.haslayer(TCP):
                port_number = " port: " + str(packet.dport)
        else:
            if packet.haslayer(UDP) or packet.haslayer(TCP):
                port_number = " port: " + str(packet.sport)
        return protocol + port_number


def get_pak_ip(pak, d_ip):
    packet = copy.deepcopy(pak)
    if packet.haslayer(IP):
        pak_ip = packet[IP].src
        if pak_ip == d_ip:
            return packet[IP].dst, 'rcv'
        else:
            return pak_ip, 'snd'
    else:
        return 'non-ip', 'none'
