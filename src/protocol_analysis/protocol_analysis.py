import copy
import csv
#import threading

from multiprocessing import Process
from multiprocessing import Manager
from scapy.utils import PcapReader
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

num_proc = 4

dst_info = {}
protocol_info = {}
filenames = []
def run(file_list, device_mac, script_dir, previous_info):
    global filenames

    print("    Reading the destination info...")
    read_dst_csv(result=previous_info)
    print("    Reading common protocol and port info...")
    read_protocol_csv(script_dir + "/protocol_analysis/protocols_info.csv")

    print("    Analyzing the protocol and port of each packet...")

    
    #all_pak = []
    results = Manager().list()
    for i in range(num_proc):
        filenames.append([])
        results.append([])

    index = 0
    for file_name in file_list:
        filenames[index].append(file_name)
        index += 1
        if index >= num_proc:
            index = 0
    print("split")
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

    print("done")
    combined_results = results[0]
    #print("c", len(combined_results))
    #for r in combined_results:
        #print("oh")
        #r.print_all()

    for i in range(num_proc - 1):
        #print("d", i)
        dst_pro_arr = results[i + 1]
        
        for dst_pro in dst_pro_arr:
            #dst_pro.print_all()
            if dst_pro in combined_results:
                index = combined_results.index(dst_pro)
                combined_results[index].add_all(dst_pro.snd, dst_pro.rcv, dst_pro.p_snd, dst_pro.p_rcv)
                #c = combined_results[index]
                #print("asdf", c.snd, c.rcv, c.p_snd, c.p_rcv)
            else:
                #print("adding")
                combined_results.append(dst_pro)

    #print("aaayyyyy")
    print("a", len(combined_results))
    for r in combined_results:
        #print("b")
        r.print_all()
    return combined_results


def dst_protocol_analysis(pid, d_mac, result_list):
    result = []

    #count = 0
    #paks = []
    #for f in filenames[pid]:
        #paks.extend(PcapReader(f))

    print(pid, "split2")
    for f in filenames[pid]:
        for p in PcapReader(f):
            packet_len = len(p)
            p_ip, snd_rcv = get_pak_ip(p, d_mac)
            if p_ip != 'non-ip' and p_ip in dst_info:
                #print(count, p_ip)
                p_protocol = get_pak_protocol(packet=p, d_mac=d_mac)
                host = dst_info[p_ip]
                prot = None
                if p_protocol in protocol_info:
                    prot = protocol_info[p_protocol]
                else:
                    prot = ProtocolPort.ProtocolPort(p_protocol, '-1', '-1', '-1', '-1')

                index = 0
                isOld = False
                for dst_pro in result:
                    if host == dst_pro.host and prot == dst_pro.protocol_port:
                        isOld = True
                        break
                    index += 1

                #print('one') 
                if isOld:
                    #index = result.index(current)
                    #current.protocol_port.print_all()
                    #result[index].protocol_port.print_all()
                    #print(count, index)
                    if snd_rcv == 'snd':
                        result[index].add_snd(packet_len)
                        result[index].add_ps(1)
                    else:
                        result[index].add_rcv(packet_len)
                        result[index].add_pr(1)

                    #print(count, index, result[index].snd, result[index].rcv, result[index].p_snd, result[index].p_rcv)

                else:
                    #print("new")
                    #current.print_all()
                    #print(count, current.host, current.protocol_port)
                    current: DestinationPro.DestinationPro
                    current = DestinationPro.DestinationPro(host, prot)
                    if snd_rcv == 'snd':
                        current.add_snd(packet_len)
                        current.add_ps(1)
                    else:
                        current.add_rcv(packet_len)
                        current.add_pr(1)
                    result.append(current)
    
            #count = count + 1
   
    print("puttt", pid, len(result_list), len(result))
    result_list[pid] = result


# For expected: 1 (well-known), -1 (unknown),
#               0.5 (potentially encrypted)
# For encrypted: 1 (encrypted), 0 (unencrypted),
#                0.5 (partially encrypted), -1 (unknown)
# return: dict (keys: Protocol&port, Expected, Encrypted)
def read_protocol_csv(file_name):
    global protocol_info

    #protocols_info = {}
    with open(file_name, mode='r', encoding='utf-8-sig') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            protocol = row["Protocol&port"]
            #encrypted = row["Encrypted"]
            #known = row["Well-known"]
            #readable = row["Human-readable"]
            #imp = row["Importance"]
            protocol_info[protocol] = ProtocolPort.ProtocolPort(protocol_port=protocol,
                                                encrypted=row["Encrypted"],
                                                expected=row["Well-known"],
                                                readable=row["Human-readable"],
                                                importance=row["Importance"])
            #protocol_info[protocol] = current
    csv_file.close()
    #protocol_info = protocols_info
    #return protocols_info


# read all the destination related info
def read_dst_csv(result: dict):
    global dst_info

    #hosts_info = {}
    total_num = result['ip'].__len__()
    index = 0
    while index < total_num:
        #host = result['host'][index]
        #party = result['party'][index]
        ip = result['ip'][index]
        #host_full = result['host_full'][index]
        #country = result['country'][index]
        #org = result['organization'][index]
        if ip not in dst_info:
            dst_info[ip] = Destination.Destination(host=result['host'][index],
                                              party=result['party'][index],
                                              ip=ip,
                                              host_full=result['host_full'][index],
                                              country=result['country'][index],
                                              org=result['organization'][index])
            #hosts_info[ip] = current
        index += 1
    #dst_info = hosts_info
    #return hosts_info


# get the protocol and port info of a packet
def get_pak_protocol(packet, d_mac):
    #if packet.src == d_mac:
    #    is_rcv = True
    #else:
    #    is_rcv = False
    #if packet.haslayer(IP):

        # get the protocol info
        #pak_copy = copy.deepcopy(packet)
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
    #packet = copy.deepcopy(pak)
    #if packet.src == d_mac:
    #    is_rcv = True
    #else:
    #    is_rcv = False
    if packet.haslayer(IP):
        if packet.src == d_mac:
            return packet[IP].dst, 'rcv'
        else:
            return packet[IP].src, 'snd'
    else:
        return 'non-ip', 'none'

