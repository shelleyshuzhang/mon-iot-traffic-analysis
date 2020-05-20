import csv
import os
import sys
import subprocess
import re
import argparse

from multiprocessing import Process
from dst_characterize import identify_party as idtpt
from party_analysis import visualization_parties as vis
from protocol_analysis import protocol_analysis as ptals
from protocol_analysis import visualization as vis_pro

software_location = "/Users/zhangshu/PycharmWorkspace/intl-iot-new-version-intest"
current_location = "/Users/zhangshu/PycharmProjects/neu_mon-iot-_network_traffic_analysis"
protocol_encrypted_dict = {"1": "encrypted", "0": "unencrypted", "-1": "unknown"}
protocol_details = {"TCP port: 443": "Https", "TCP port: 80": "Http", "UDP port: 80": "Http"}

devnull = open(os.devnull, "w")
path = sys.argv[0]
script_dir = os.path.dirname(path)
if script_dir == "":
    script_dir = "."

RED = "\033[31;1m"
END = "\033[0m"

usage_stm = """
Usage: python3 {prog_name} -i PCAP_DIR -m MAC_ADDR -s IMC_DIR [OPTION]...

Performs destination and protocol analysis. Determines the percentage of first,
support, third, and local party traffic. Produces a CSV file which includes
traffic party and organization. Several plots are also generated for visualization.

Example: python3 {prog_name} -i echodot_pcaps/ -m 18:74:2e:41:4d:35 -s ../intl-iot/ -d Amazon -p 4

Required arguments:
  -i PCAP_DIR path to the directory containing input pcap files for analysis
  -m MAC_ADDR MAC address of the device that generated the data in PCAP_DIR
  -s IMC_DIR  path to the directory containing the code accompanying the paper
                titled "Information Exposure From Consumer IoT Devices: A
                Multidimensional, Network-Informed Measurement Approach" in
                proceedings of the ACM Internet Measurement Conference 2019 (IMC
                2019); the code can be found here: https://github.com/NEU-SNS/intl-iot

Optional arguments:
  -d DEV_MFR  company that created the device that generated the data in PCAP_DIR;
                used to identify first parties (Default = unknown)
  -f FIG_DIR  path to a directory to place the generated plots; will be generated
                if it does not currently exist (Default = plots/)
  -o OUT_CSV  path to the output CSV file; if it exists, results will be appended,
                else, it will be created (Default = results.csv)
  -p NUM_PROC number of CPU processes to use to run the destination analysis portion
                (Default = 1)
  -h          print this usage statement and exit
                
For more information, see the README.""".format(prog_name=path)


# isError is either 0 or 1
def print_usage(isError):
    if isError:
        print(usage_stm, file=sys.stderr)
    else:
        print(usage_stm)
    exit(isError)


def not_valid_dir(direc):
    errors = False
    if not os.path.isdir(direc):
        errors = True
        print("%s%s: Error: The input pcap directory \"%s\" is not a directory.%s"
              % (RED, path, direc, END), file=sys.stderr)
    else:
        if not os.access(direc, os.R_OK):
            errors = True
            print("%s%s: Error: The \"%s\" directory does not have read permission.%s"
                  % (RED, path, direc, END), file=sys.stderr)
        if not os.access(direc, os.X_OK):
            errors = True
            print("%s%s: Error: The \"%s\" directory does not have execute permission.%s"
                  % (RED, path, direc, END), file=sys.stderr)

    return errors


# Run analyze.py
def run_dest_pipeline(raw_files_list, mac, tmp_csv):
    for f in raw_files_list:
        print("Running python3", software_location, "-i", f, "-m", mac, "-o", tmp_csv)
        ret = subprocess.call(["python3", software_location, "-i", f, "-m", mac, "-o", tmp_csv],
                              stdout=devnull)
        if ret < 0:
            print("UHOH")
            exit(ret)


if __name__ == "__main__":
    print("Running %s..." % path)

    # Options
    parser = argparse.ArgumentParser(usage=usage_stm, add_help=False)
    parser.add_argument("-i", dest="dir_name", default="")
    parser.add_argument("-m", dest="mac", default="")
    parser.add_argument("-s", dest="software_location", default="")
    parser.add_argument("-d", dest="company", default="unknown")
    parser.add_argument("-f", dest="fig_dir", default="plots")
    parser.add_argument("-o", dest="out_csv", default="results.csv")
    parser.add_argument("-p", dest="num_proc", default="")
    parser.add_argument("-h", dest="help", action="store_true", default=False)
    args = parser.parse_args()

    if args.help:
        print_usage(0)

    dir_name = args.dir_name
    mac = args.mac
    software_location = args.software_location
    company: str = args.company
    company = company.lower()
    num_proc = 1

    # Error checking arguments
    errors = False
    if dir_name == "":
        errors = True
        print("%s%s: Error: Input pcap directory (-i) required.%s"
              % (RED, path, END), file=sys.stderr)
    elif not_valid_dir(dir_name):
        errors = True

    if mac == "":
        errors = True
        print("%s%s: Error: MAC address (-m) required.%s" % (RED, path, END), file=sys.stderr)
    elif not re.match("([0-9a-f]{2}[:]){5}[0-9a-f]{2}$", mac):
        errors = True
        print("%s%s: Error: Invalid MAC address \"%s\". Valid format: xx:xx:xx:xx:xx:xx%s"
              % (RED, path, mac, END), file=sys.stderr)

    if software_location == "":
        errors = True
        print("%s%s: Error: IMC19 directory (-s) required.%s" % (RED, path, END), file=sys.stderr)
    else:
        software_location += "/destination/analyze.py"
        if not_valid_dir(os.path.dirname(os.path.dirname(software_location))):
            errors = True
        elif not_valid_dir(os.path.dirname(software_location)):
            errors = True
        else:
            if not os.path.isfile(software_location):
                errors = True
                print("%s%s: Error: The script \"%s\" is missing.%s"
                      % (RED, path, software_location, END), file=sys.stderr)
            elif not os.access(software_location, os.R_OK):
                errors = True
                print("%s%s: Error: The script \"%s\" does not have read permission.%s"
                      % (RED, path, software_location, END), file=sys.stderr)

    if not args.out_csv.endswith(".csv"):
        errors = True
        print("%s%s: Error: The output file should be a CSV (.csv) file. Received \"%s\".%s"
              % (RED, path, args.out_csv, END), file=sys.stderr)

    bad_proc = False
    try:
        if args.num_proc != "":
            if int(args.num_proc) > 0:
                num_proc = int(args.num_proc)
            else:
                bad_proc = True
    except:
        bad_proc = True

    if bad_proc:
        errors = True
        print("%s%s: Error: The number of processes must be a positive integer. Received \"%s\".%s"
              % (RED, path, args.num_proc, END), file=sys.stderr)

    if errors:
        print_usage(1)
    # End error checking

    raw_files = []
    index = 0
    # Create the groups to run analyze.py with processes
    while index < num_proc:
        raw_files.append([])
        index += 1

    index = 0
    # Split the pcap files into num_proc groups
    for root, dirs, files in os.walk(dir_name):
        for filename in files:
            if filename.endswith("pcap") and not filename.startswith("."):
                raw_files[index].append(root + "/" + filename)
                index += 1
                if index >= num_proc:
                    index = 0

    procs = []
    tmp_csv = args.fig_dir + "/" + company + "_tmp.csv"
    # Run analyze.py with num_proc processes
    print("Analyzing input pcap files...")
    for files in raw_files:
        p = Process(target=run_dest_pipeline, args=(files, mac, tmp_csv))
        procs.append(p)
        p.start()

    for p in procs:
        p.join()

    # characterize the parties
    print("Characterizing the parties...")
    result = idtpt.run_extract_third_parties(tmp_csv, script_dir, company)

    # check if the traffic is encrypted
    print("Analyzing traffic encryption...")
    file_list = []
    for files in raw_files:
        file_list.extend(files)
    # result is a list of DestinationPro that
    # contains all the info
    result = ptals.run(file_list=file_list,
                       device_mac=mac,
                       script_dir=script_dir,
                       previous_info=result)

    out_csv = args.out_csv
    # write the result to a csv file
    print("Results written to \"" + out_csv + "\"")
    out_csv_dir = os.path.dirname(out_csv)
    if out_csv_dir != "" and not os.path.isdir(out_csv_dir):
        os.system("mkdir -pv " + out_csv_dir)
    with open(file=out_csv, mode='w') as result_csv_file:
        fieldnames = ('ip', 'host', 'host_full', 'traffic_snd',
                      'traffic_rcv', 'packet_snd', 'packet_rcv', 'country',
                      'party', 'organization', 'protocol&port', 'encryption')
        writer = csv.DictWriter(result_csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for dp in result:
            dst = dp.host
            pro = dp.protocol_port
            send = dp.snd
            received = dp.rcv
            p_snd = dp.p_snd
            p_rcv = dp.p_rcv
            encrypted = protocol_encrypted_dict[pro.encrypted]
            protocol_p = pro.protocol_port
            if protocol_p in protocol_details:
                protocol_p = protocol_details[protocol_p]
            writer.writerow({'ip': dst.ip,
                             'host': dst.host,
                             'host_full': dst.host_full,
                             'traffic_snd': send,
                             'traffic_rcv': received,
                             'packet_snd': p_snd,
                             'packet_rcv': p_rcv,
                             'country': dst.country,
                             'party': dst.party,
                             'organization': dst.organization,
                             'protocol&port': protocol_p,
                             'encryption': encrypted})
        result_csv_file.close()

    # analyze the percentage of each party in all hosts and the amount of traffic
    # sent to each party, and generate the plots
    print("Calculating party percentages and generating plots...")
    vis.calculate_party_percentage(args.out_csv, company, args.fig_dir)

    # analyze the protocol and ports use; calculate the amount of traffic sent to
    # each destination and protocols, and visualizing the results as plots
    print("Calculating protocol percentages for encryption analysis and generating plots...")
    vis_pro.run(result=result, company=company)
