import os
import sys
import subprocess
import re
import argparse

from multiprocessing import Process
from dst_characterize import identify_party as idtpt
from party_analysis import visualization_parties as vis

software_location = "/Users/zhangshu/PycharmWorkspace/intl-iot-new-version-intest"
current_location = "/Users/zhangshu/PycharmProjects/neu_mon-iot-_network_traffic_analysis"
num_proc = 4
devnull = open(os.devnull, "w")
script_dir = os.path.dirname(sys.argv[0])
if script_dir == "":
    script_dir = "."

RED = "\033[31;1m"
END = "\033[0m"

usage_stm = """
Usage: python3 {prog_name} -i PCAP_DIR -m MAC_ADDR -s IMC_DIR [OPTION]...

Performs destination and protocol analysis. Determines the percentage of first, support,
third, and local party traffic. Produces a CSV file which includes traffic party and
organization. Several plots are also generated for visualization.

Example: python3 {prog_name} -i echodot_pcaps/ -m 18:74:2e:41:4d:35 -s ../intl-iot/ -d Amazon

Arguments:
  -i PCAP_DIR the directory containing input pcap files for analysis; option required
  -m MAC_ADDR the MAC address of the device that generated the data in pcap_dir;
                option required
  -s IMC_DIR  the path to the directory containing the code accompanying the paper
                titled "Information Exposure From Consumer IoT Devices: A
                Multidimensional, Network-Informed Measurement Approach" in
                proceedings of the ACM Internet Measurement Conference 2019 (IMC
                2019); the code can be found here: https://github.com/NEU-SNS/intl-iot;
                option required
  -d DEV_MFR  the company that created the device that generated the data in pcap_dir;
                used to identify first parties (Default = unknown)
  -f FIG_DIR  the directory to place the generated plots; will be generated if it
                does not currently exist (Default = plots/)
  -o OUT_CSV  the output CSV file; if it exists, results will be appended, else it
                will be created (Default = result.csv)
                
For more information, see the README.""".format(prog_name=sys.argv[0])

def print_usage():
    print(usage_stm, file=sys.stderr)
    exit(1)

def not_valid_dir(direc):
    errors = False
    if not os.path.isdir(direc):
        errors = True
        print("%s%s: Error: The input pcap directory \"%s\" does not exist.%s" % (RED, path, direc, END), file=sys.stderr)
    else:
        if not os.access(direc, os.R_OK):
            errors = True
            print("%s%s: Error: The \"%s\" directory does not have read permission.%s" % (RED, path, direc, END), file=sys.stderr)
        if not os.access(direc, os.X_OK):
            errors = True
            print("%s%s: Error: The \"%s\" directory does not have execute permission.%s" % (RED, path, direc, END), file=sys.stderr)

    return errors


#Run analyze.py
def run_dest_pipeline(raw_files_list, mac, tmp_csv):
    for f in raw_files_list:
        print("Running python3", software_location, "-i", f, "-m", mac, "-o", tmp_csv)
        ret = subprocess.call(["python3", software_location, "-i", f, "-m", mac, "-o", tmp_csv], stdout=devnull)
        if ret < 0:
            print("UHOH")
            exit(ret)

if __name__ == "__main__":
    path = sys.argv[0]
    print("Running %s..." % path)

    #Options
    parser = argparse.ArgumentParser(usage=usage_stm)
    parser.add_argument("-i", dest="dir_name", default="")
    parser.add_argument("-m", dest="mac", default="")
    parser.add_argument("-s", dest="software_location", default="")
    parser.add_argument("-d", dest="company", default="unknown")
    parser.add_argument("-f", dest="fig_dir", default="plots")
    parser.add_argument("-o", dest="out_csv", default="result.csv")
    args = parser.parse_args()

    dir_name = args.dir_name
    mac = args.mac
    software_location = args.software_location
    company = args.company

    #Error checking arguments
    errors = False
    if dir_name == "":
        errors = True
        print("%s%s: Error: Input pcap directory (-i) required.%s" % (RED, path, END), file=sys.stderr)
    elif not_valid_dir(dir_name):
        errors = True

    if mac == "":
        errors = True
        print("%s%s: Error: MAC address (-m) required.%s" % (RED, path, END), file=sys.stderr)
    elif not re.match("([0-9a-f]{2}[:]){5}[0-9a-f]{2}$", mac):
        errors = True
        print("%s%s: Error: Invalid MAC address \"%s\". Valid format: xx:xx:xx:xx:xx:xx%s" % (RED, path, mac, END))

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
                print("%s%s: Error: The script \"%s\" is missing.%s" % (RED, path, software_location, END), file=sys.stderr)
            elif not os.access(software_location, os.R_OK):
                errors = True
                print("%s%s: Error: The script \"%s\" does not have read permission.%s" % (RED, path, software_location, END))

    if not args.out_csv.endswith(".csv"):
        errors = True
        print("%s%s: Error: The output file should be a .csv file. Received \"%s\"%s" % (RED, path, args.out_csv, END), file=sys.stderr)

    if errors:
        print_usage()
    #End error checking

    raw_files = []
    index = 0
    #Create the groups to run analyze.py with processes
    while index < num_proc:
        raw_files.append([])
        index += 1

    index = 0
    #Split the pcap files into num_proc groups
    for root, dirs, files in os.walk(dir_name):
        for filename in files:
            if filename.endswith("pcap") and not filename.startswith("."):
                raw_files[index].append(root + "/" + filename)
                index += 1
                if index >= num_proc:
                    index = 0

    procs = []
    tmp_csv = args.fig_dir + "/" + company + "_tmp.csv"
    #Run analyze.py with num_proc processes
    print("Analyzing input pcap files...")
    for files in raw_files:
        p = Process(target=run_dest_pipeline, args=(files, mac, tmp_csv))
        procs.append(p)
        p.start()
    
    for p in procs:
        p.join()


    # characterize the parties
    print("Characterizing the parties...")
    idtpt.run_extract_third_parties(tmp_csv, script_dir, args.out_csv, company)

    # analyze the percentage of each party in all hosts and the amount of traffic
    # sent to each party, and generate the plots
    print("Calculating party percentages and generating plots...")
    vis.calculate_party_percentage(args.out_csv, company, args.fig_dir)
