from csv import reader

from . import Destination
from . import DestinationPro
from . import ProtocolPort


def read_prot_port_info(info):
    prot_info = {"HTTP": ["1", "1", "1"], "HTTPS": ["1", "0", "1"]}
    with open(info, "r") as f:
        csv_reader = reader(f)
        next(csv_reader)
        for row in csv_reader:
            prot_port = row[0].upper()
            well_known = row[1]
            human_readable = row[2]
            imp = row[4]
            prot_info[prot_port] = [well_known, human_readable, imp]

    return prot_info


#constructs DestinationPros from an output CSV
#useful for generating plots without having to rerun analyses
def load(script_dir, out_csv_path):
    print("Loading results from %s..." % out_csv_path)
    prot_enc_dict = {"encrypted": "1", "unencrypted": "0", "unknown": "-1"}
    prots_info = read_prot_port_info(script_dir + "/protocol_analysis/protocols_info.csv")
    dst_pro = []
    with open(out_csv_path, "r") as f:
        csv_reader = reader(f)
        next(csv_reader)
        for row in csv_reader:
            ip = row[0]
            host = row[1]
            host_full = row[2]
            bytes_snd = row[3]
            bytes_rcv = row[4]
            pckt_snd = row[5]
            pckt_rcv = row[6]
            country = row[7]
            party = row[8]
            org = row[9]
            prot_port = row[10]
            enc = row[11]

            dst = Destination.Destination(ip, host, party, host_full, country, org)
           
            try:
                prot_info = prots_info[prot_port.upper()]
                prot = ProtocolPort.ProtocolPort(prot_port, prot_enc_dict[enc.lower()],
                                                 prot_info[0], prot_info[1], prot_info[2])
            except KeyError:
                prot = ProtocolPort.ProtocolPort(prot_port, '-1', '-1', '-1', '-1')

            dp = DestinationPro.DestinationPro(dst, prot)
            dp.add_all(int(bytes_snd), int(bytes_rcv), int(pckt_snd), int(pckt_rcv))

            dst_pro.append(dp)

    return dst_pro
