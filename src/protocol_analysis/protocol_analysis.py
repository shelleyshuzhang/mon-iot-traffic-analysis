import csv
import os
from multiprocessing import Manager
from multiprocessing import Process

####### must import the packet in scapy in order to see the results #######
from scapy import *
from scapy.layers import *
from scapy.layers.dns import *
from scapy.layers.inet import *
from scapy.utils import PcapReader

from protocol_analysis import Destination, DestinationPro, ProtocolPort

protocol_known_dict = {"1": "well-known", "-1": "unknown",
                       "0.5": "registered", "0": "not-well-known"}
protocol_readable_dict = {"1": "human-readable", "0": "human-unreadable",
                          "0.5": "partially human-readable", "-1": "unknown"}
protocol_encrypted_dict = {"1": "encrypted", "0": "unencrypted", "-1": "unknown"}
protocol_importance_dict = {"1": "important", "0": "unimportant", "-1": "unknown"}

dst_info = {}
protocol_info = {}
filenames = []


def run(dir_name, device_mac, script_dir, previous_info, num_proc):
    global filenames

    print("    Reading the destination info...")
    read_dst_csv(result=previous_info)
    print("    Reading common protocol and port info...")
    read_protocol_csv(script_dir + "/protocol_analysis/protocols_info.csv")

    print("    Analyzing the protocol and port of each packet...")

    results = Manager().list()
    for i in range(num_proc):
        filenames.append([])
        results.append([])

    index = 0
    for root, dirs, files in os.walk(dir_name):
        for filename in files:
            if filename.endswith(".pcap") and not filename.startswith("."):
                filenames[index].append(root + "/" + filename)
                index += 1
                if index >= num_proc:
                    index = 0
    
    procs = []
    pid = 0
    for i in range(num_proc):
        p = Process(target=dst_protocol_analysis,
                    args=(pid, device_mac, results))
        procs.append(p)
        p.start()
        pid += 1

    for p in procs:
        p.join()

    combined_results = results[0]

    for i in range(num_proc - 1):
        dst_pro_arr = results[i + 1]

        for dst_pro in dst_pro_arr:
            if dst_pro in combined_results:
                index = combined_results.index(dst_pro)
                combined_results[index].add_all(dst_pro.snd, dst_pro.rcv, dst_pro.p_snd, dst_pro.p_rcv)
            else:
                combined_results.append(dst_pro)

    return combined_results


def dst_protocol_analysis(pid, d_mac, result_list):
    result = []

    for f in filenames[pid]:
        for p in PcapReader(f):
            packet_len = len(p)
            p_ip, snd_rcv = get_pak_ip(p, d_mac)
            if p_ip != 'non-ip' and p_ip in dst_info:
                p_protocol = get_pak_protocol(packet=p, d_mac=d_mac)
                host = dst_info[p_ip]
                if p_protocol in protocol_info:
                    prot = protocol_info[p_protocol]
                else:
                    prot = ProtocolPort.ProtocolPort(p_protocol, '-1', '-1', '-1', '-1')

                index = 0
                is_old = False
                for dst_pro in result:
                    if host == dst_pro.host and prot == dst_pro.protocol_port:
                        is_old = True
                        break
                    index += 1

                if is_old:
                    if snd_rcv == 'snd':
                        result[index].add_snd(packet_len)
                        result[index].add_ps(1)
                    else:
                        result[index].add_rcv(packet_len)
                        result[index].add_pr(1)

                else:
                    current: DestinationPro.DestinationPro
                    current = DestinationPro.DestinationPro(host, prot)
                    if snd_rcv == 'snd':
                        current.add_snd(packet_len)
                        current.add_ps(1)
                    else:
                        current.add_rcv(packet_len)
                        current.add_pr(1)
                    result.append(current)

    result_list[pid] = result


# For expected: 1 (well-known), -1 (unknown),
#               0.5 (potentially encrypted)
# For encrypted: 1 (encrypted), 0 (unencrypted),
#                0.5 (partially encrypted), -1 (unknown)
# return: dict (keys: Protocol&port, Expected, Encrypted)
def read_protocol_csv(file_name):
    global protocol_info

    with open(file_name, mode='r', encoding='utf-8-sig') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            protocol = row["Protocol&port"]
            protocol_info[protocol] = ProtocolPort.ProtocolPort(protocol_port=protocol,
                                                                encrypted=row["Encrypted"],
                                                                expected=row["Well-known"],
                                                                readable=row["Human-readable"],
                                                                importance=row["Importance"])
    csv_file.close()


# read all the destination related info
def read_dst_csv(result: dict):
    global dst_info

    total_num = result['ip'].__len__()
    index = 0
    while index < total_num:
        ip = result['ip'][index]
        if ip not in dst_info:
            dst_info[ip] = Destination.Destination(host=result['host'][index],
                                                   party=result['party'][index],
                                                   ip=ip,
                                                   host_full=result['host_full'][index],
                                                   country=result['country'][index],
                                                   org=result['organization'][index])
        index += 1


# get the protocol and port info of a packet
def get_pak_protocol(packet, d_mac):
    # get the protocol info
    protocol = packet.lastlayer().name
    if protocol == "Raw":
        pros = list(packet.iterpayloads())
        protocol = pros[pros.__len__() - 2].name
    if not protocol.startswith("IGMPv3mr"):
        protocol = protocol.split()[0]
    else:
        protocol = "IGMPv3"

    # get port number information
    port_number = ""
    if packet.src == d_mac:
        if packet.haslayer(UDP) or packet.haslayer(TCP):
            port_number = " port: " + str(packet.dport)
    else:
        if packet.haslayer(UDP) or packet.haslayer(TCP):
            port_number = " port: " + str(packet.sport)
    return protocol + port_number


# get the IP of the packet and whether
# it is sent or received
def get_pak_ip(packet, d_mac):
    if packet.haslayer(IP):
        if packet.src == d_mac:
            return packet[IP].dst, 'rcv'
        else:
            return packet[IP].src, 'snd'
    else:
        return 'non-ip', 'none'
