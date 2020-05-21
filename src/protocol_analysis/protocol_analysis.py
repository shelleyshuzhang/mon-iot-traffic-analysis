import copy
import csv

from scapy.utils import rdpcap
from protocol_analysis import Destination, DestinationPro, ProtocolPort

####### must import the packet in scapy in order to see the results #######
from scapy.layers.dns import *
from scapy import *
from scapy.layers import *
from scapy.contrib.igmp import IGMP
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import *
from scapy.layers.ntp import NTP

protocol_known_dict = {"1": "well-known", "-1": "unknown",
                       "0.5": "registered", "0": "not-well-known"}
protocol_readable_dict = {"1": "human-readable", "0": "human-unreadable",
                          "0.5": "partially human-readable", "-1": "unknown"}
protocol_encrypted_dict = {"1": "encrypted", "0": "unencrypted", "-1": "unknown"}
protocol_importance_dict = {"1": "important", "0": "unimportant", "-1": "unknown"}


def run(file_list, device_mac, script_dir, previous_info):
    all_pak = []
    for file_name in file_list:
        all_pak.extend(rdpcap(file_name))
    result = dst_protocol_analysis(packets=all_pak,
                                   d_mac=device_mac,
                                   previous_info=previous_info,
                                   protocol_file=script_dir + '/protocol_analysis/protocols_info.csv')
    return result


def dst_protocol_analysis(packets, d_mac, previous_info, protocol_file):
    result = []

    print("    Reading the destination info...")
    dst_info: dict = read_dst_csv(result=previous_info)
    print("    Reading common protocol and port info...")
    protocol_info: dict = read_protocol_csv(protocol_file)

    print("    Analyzing the protocol and port of each packet...")
    for p in packets:
        p_ip, snd_rcv = get_pak_ip(p, d_mac)
        if p_ip != 'non-ip' and p_ip in dst_info:
            p_protocol = get_pak_protocol(packet=p,
                                          d_mac=d_mac)
            current: DestinationPro.DestinationPro
            if p_protocol in protocol_info:
                current = DestinationPro.DestinationPro(dst_info[p_ip],
                                                        protocol_info[p_protocol])
            else:
                current = DestinationPro.DestinationPro(dst_info[p_ip],
                                                        ProtocolPort.ProtocolPort(protocol_port=p_protocol,
                                                                                  encrypted='-1',
                                                                                  expected='-1',
                                                                                  readable='-1',
                                                                                  importance='-1'))
            if current in result:
                index = result.index(current)
                if snd_rcv == 'snd':
                    result[index].add_snd(len(p))
                    result[index].add_ps(1)
                else:
                    result[index].add_rcv(len(p))
                    result[index].add_pr(1)
            else:
                if snd_rcv == 'snd':
                    current.add_snd(len(p))
                    current.add_ps(1)
                else:
                    current.add_rcv(len(p))
                    current.add_pr(1)
                result.append(current)
    return result


# For expected: 1 (well-known), -1 (unknown),
#               0.5 (potentially encrypted)
# For encrypted: 1 (encrypted), 0 (unencrypted),
#                0.5 (partially encrypted), -1 (unknown)
# return: dict (keys: Protocol&port, Expected, Encrypted)
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
            current = ProtocolPort.ProtocolPort(protocol_port=protocol,
                                                encrypted=encrypted,
                                                expected=known,
                                                readable=readable,
                                                importance=imp)
            protocols_info[protocol] = current
    csv_file.close()
    return protocols_info


# read all the destination related info
def read_dst_csv(result: dict):
    hosts_info = {}
    total_num = result['ip'].__len__()
    index = 0
    while index < total_num:
        host = result['host'][index]
        party = result['party'][index]
        ip = result['ip'][index]
        host_full = result['host_full'][index]
        country = result['country'][index]
        org = result['organization'][index]
        if ip not in hosts_info:
            current = Destination.Destination(host=host,
                                              party=party,
                                              ip=ip,
                                              host_full=host_full,
                                              country=country,
                                              org=org)
            hosts_info[ip] = current
        index += 1
    return hosts_info


# get the protocol and port info of a packet
def get_pak_protocol(packet, d_mac):
    if packet.src == d_mac:
        is_rcv = True
    else:
        is_rcv = False
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
        if is_rcv:
            if packet.haslayer(UDP) or packet.haslayer(TCP):
                port_number = " port: " + str(packet.dport)
        else:
            if packet.haslayer(UDP) or packet.haslayer(TCP):
                port_number = " port: " + str(packet.sport)
        return protocol + port_number


# get the IP of the packet and whether
# it is sent or received
def get_pak_ip(pak, d_mac):
    packet = copy.deepcopy(pak)
    if packet.src == d_mac:
        is_rcv = True
    else:
        is_rcv = False
    if packet.haslayer(IP):
        if is_rcv:
            return packet[IP].dst, 'rcv'
        else:
            return packet[IP].src, 'snd'
    else:
        return 'non-ip', 'none'
