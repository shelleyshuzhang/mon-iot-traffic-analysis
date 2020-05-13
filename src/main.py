import os
import subprocess
from dst_characterize import identify_party as idtpt
from party_analysis import visualization_parties as vis

software_location = "/Users/zhangshu/PycharmWorkspace/intl-iot-new-version-intest"
current_location = "/Users/zhangshu/PycharmProjects/neu_mon-iot-_network_traffic_analysis"

if __name__ == "__main__":
    dir_name = input("Please enter the directory of input pcap files.\n")
    mac = input("What's the mac address of the device?\n")
    company = input("What's the device's manufacturer? (ex: amazon)\n"
                    "Please enter 'unknown' if you don't know.\n")
    max_files = int(input("How many files do you want to analyze?\n"))
    software_location = input("Please enter the full path for ICM 2019 software\n")
    software_location += "/destination"

    raw_files = []
    for root, dirs, files in os.walk(dir_name):
        for filename in files:
            if filename.endswith("pcap") and not filename.startswith("."):
                raw_files.append(root + "/" + filename)

    # subprocess.Popen("ls; pwd", cwd="/Users/zhangshu", shell=True)

    # commands = ''
    # for f in raw_files:
    #     print(f)
    #     commands += "python3 analyze.py -i " + f + " -m " + mac + "; "
    # subprocess.Popen(commands,
    #                  cwd=software_location,
    #                  shell=True)

    session_list = []
    index = 0
    while index < max_files:
        f = raw_files[index]
        session = subprocess.Popen("python3 analyze.py -i " + f + " -m " + mac,
                                   cwd=software_location,
                                   shell=True)
        session_list.append(session)
        index += 1

    input_csv_file = software_location + "/experiment"
    all_finished = []
    for s in session_list:
        all_finished.append(s.poll())
    while None in all_finished:
        pass

    # characterize the parties
    idtpt.run_extract_third_parties(input_csv_file=input_csv_file, company=company)

    # analyze the percentage of each party in all hosts and the amount of traffic
    # sent to each party, and generate the plots
    vis.calculate_party_percentage(csv_filename="result", company=company)
