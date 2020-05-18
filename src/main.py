import os
import subprocess
from multiprocessing import Process
from dst_characterize import identify_party as idtpt
from party_analysis import visualization_parties as vis

software_location = "/Users/zhangshu/PycharmWorkspace/intl-iot-new-version-intest"
current_location = "/Users/zhangshu/PycharmProjects/neu_mon-iot-_network_traffic_analysis"
company = 'amazon'
num_proc = 4
devnull = open(os.devnull, "w")


# Run analyze.py
def run_dest_pipeline(raw_files_list, mac):
    for f in raw_files_list:
        print("Running python3 " + software_location + "/analyze.py -i " + f + " -m " + mac)
        ret = subprocess.call(["python3", software_location + "/analyze.py", "-i", f, "-m", mac], stdout=devnull)
        if ret < 0:
            print("UHOH")
            exit(ret)


if __name__ == "__main__":
    dir_name = input("Please enter the directory of input pcap files.\n")
    mac = input("What's the mac address of the device?\n")
    company = input("What's the device's manufacturer? (ex: amazon)\n"
                    "Please enter 'unknown' if you don't know.\n")
    # software_location = input("Please enter the full path for ICM 2019 software\n")
    software_location += "/destination"

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
    # Run analyze.py with num_proc processes
    for files in raw_files:
        p = Process(target=run_dest_pipeline, args=(files, mac))
        procs.append(p)
        p.start()

    for p in procs:
        p.join()

    input_csv_file = software_location + "/experiment"

    # characterize the parties
    print("Characterizing the parties")
    idtpt.run_extract_third_parties(input_csv_file=input_csv_file, company=company)

    # analyze the percentage of each party in all hosts and the amount of traffic
    # sent to each party, and generate the plots
    print("More Analysis")
    vis.calculate_party_percentage(csv_filename="result", company=company)
