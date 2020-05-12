import os
import subprocess

software_location = "/Users/zhangshu/PycharmWorkspace/intl-iot-new-version-intest/destination"
current_location = "/Users/zhangshu/PycharmProjects/neu_mon-iot-_network_traffic_analysis"

if __name__ == "__main__":
    dir_name = input("Please enter the directory of input pcap files.\n")
    mac = input("What's the mac address of the device?\n")
    company = input("What's the device's manufacturer? (ex: amazon)\n"
                    "Please enter 'Unknown' if you don't know.\n")
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
    for f in raw_files:
        session = subprocess.Popen("python3 analyze.py -i " + f + " -m " + mac,
                                   cwd=software_location,
                                   shell=True)
        session_list.append(session)

    input_csv_file = software_location + "/experiment.csv"
    all_finished = []
    for s in session_list:
        all_finished.append(s.poll())
    while None in all_finished:
        for s in session_list:
            all_finished.append(s.poll())
    run_extract_third_parties(input_csv_file=input_csv_file, company=company)
