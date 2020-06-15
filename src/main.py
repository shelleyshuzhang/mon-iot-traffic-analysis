import csv
import os
import pickle
import sys
import re
import argparse
import time

from dst_characterize import identify_party as idtpt
from party_analysis import visualization_parties as vis
from protocol_analysis import protocol_analysis as ptals
from protocol_analysis import visualization_protocols as vis_pro
from abroad_traffic_analysis import identify_abroad_adr as dtf_ab_adr
from abroad_traffic_analysis import visualization_abroad as vis_abr
import Constants as c

software_location = "/Users/zhangshu/PycharmWorkspace/intl-iot-new-version-intest"
current_location = "/Users/zhangshu/PycharmProjects/neu_mon-iot-_network_traffic_analysis"
protocol_encrypted_dict = {"1": "encrypted", "0": "unencrypted", "-1": "unknown"}
protocol_details = {"TCP port: 443": "Https", "TCP port: 80": "Http",
                    "UDP port: 80": "Http", "UDP port: 443": "Https"}


# isError is either 0 or 1
def print_usage(isError):
    if isError:
        print(c.USAGE_STM, file=sys.stderr)
    else:
        print(c.USAGE_STM)
    exit(isError)


def not_valid_dir(direc, dir_print):
    errors = False
    if not os.path.isdir(direc):
        errors = True
        print(c.INVAL % (dir_print + " directory", direc, "directory"), file=sys.stderr)
    else:
        if not os.access(direc, os.R_OK):
            errors = True
            print(c.NO_PERM % ("directory", direc, "read"), file=sys.stderr)
        if not os.access(direc, os.X_OK):
            errors = True
            print(c.NO_PERM % ("directory", direc, "execute"), file=sys.stderr)

    return errors


def is_pos(num, num_desc):
    is_pos = False
    try:
        if int(num) > 0:
            is_pos = True
    except ValueError:
        pass

    if not is_pos:
        print(c.NON_POS % (num_desc, num), file=sys.stderr)

    return is_pos


if __name__ == "__main__":
    start_time = time.time()

    # Options
    parser = argparse.ArgumentParser(usage=c.USAGE_STM, add_help=False)
    parser.add_argument("-i", dest="dir_name", default="")
    parser.add_argument("-m", dest="mac", default="")
    parser.add_argument("-v", dest="in_csv", default="")
    parser.add_argument("-s", dest="software_location", default="")
    parser.add_argument("-c", dest="company", default="unknown")
    parser.add_argument("-f", dest="fig_dir", default="plots")
    parser.add_argument("-o", dest="out_csv", default="results.csv")
    parser.add_argument("-d", dest="dst_types", default="")
    parser.add_argument("-p", dest="plot_types", default="")
    parser.add_argument("-l", dest="linear", action="store_true", default=False)
    parser.add_argument("-t", dest="dpi", default="72")
    parser.add_argument("-n", dest="num_proc", default="1")
    parser.add_argument("-h", dest="help", action="store_true", default=False)
    args = parser.parse_args()

    if args.help:
        print_usage(0)

    print("Running %s..." % c.PATH)
    print("Start time: %s\n" % time.strftime("%A %d %B %Y %H:%M:%S %Z", time.localtime(start_time)))
    # Thursday 11 June 2020 11:37:02 EDT

    dir_name = args.dir_name
    mac = args.mac
    software_location = args.software_location
    company: str = args.company
    company = company.lower()
    dst_types = args.dst_types.split(",")
    # for each type, make lowercase, remove trailing/leading white space
    dst_types = [dst_type.strip().lower() for dst_type in dst_types]
    plot_types = args.plot_types.split(",")
    plot_types = [plot_type.strip().lower() for plot_type in plot_types]
    if not args.linear:  # remove duplicates if not generating plots linearly
        dst_types = list(dict.fromkeys(dst_types))
        plot_types = list(dict.fromkeys(plot_types))

    # Error checking arguments
    errors = False
    if dir_name == "":
        errors = True
        print(c.NO_IN_DIR, file=sys.stderr)
    elif not_valid_dir(dir_name, "Input pcap"):
        errors = True

    if mac == "":
        errors = True
        print(c.NO_MAC, file=sys.stderr)
    elif not re.match("([0-9a-f]{2}[:]){5}[0-9a-f]{2}$", mac):
        errors = True
        print(c.INVAL_MAC % mac, file=sys.stderr)

    if args.in_csv == "" and software_location == "":
        errors = True
        print(c.NO_IMC_OR_CSV, file=sys.stderr)
    elif args.in_csv != "":
        if not args.in_csv.endswith(".csv"):
            errors = True
            print(c.WRONG_EXT % ("Input file", "CSV (.csv)", args.in_csv), file=sys.stderr)
        elif not os.path.isfile(args.in_csv):
            errors = True
            print(c.INVAL % ("Input CSV", args.in_csv, "file"), file=sys.stderr)
    else:
        software_location += "/destination/analyze.py"
        if not_valid_dir(os.path.dirname(os.path.dirname(software_location)), "IMC'19"):
            errors = True
        elif not_valid_dir(os.path.dirname(software_location), "Destination analysis"):
            errors = True
        else:
            if not os.path.isfile(software_location):
                errors = True
                print(c.MISSING % (software_location, "directory"), file=sys.stderr)
            elif not os.access(software_location, os.R_OK):
                errors = True
                print(c.NO_PERM % ("directory", software_location, "read"), file=sys.stderr)

    if not args.out_csv.endswith(".csv"):
        errors = True
        print(c.WRONG_EXT % ("Output file", "CSV (.csv)", args.out_csv), file=sys.stderr)

    for dst_type in dst_types:
        if dst_type not in ("sld", "fqdn", "org", ""):
            errors = True
            print(c.INVAL_DST % dst_type, file=sys.stderr)

    for plot_type in plot_types:
        if plot_type not in ("pieplot", "barhplot", ""):
            errors = True
            print(c.INVAL_PLT % plot_type, file=sys.stderr)

    if not is_pos(args.num_proc, "Number of processes") or not is_pos(args.dpi, "DPI"):
        errors = True

    if errors:
        print_usage(1)
    # End error checking

    out_csv = args.out_csv
    pkl_name = out_csv.split(".")[0]
    pkl_name += '_destinations.pkl'


    def save_object(obj, filename):
        with open(filename, 'wb') as output:
            pickle.dump(obj, output, pickle.HIGHEST_PROTOCOL)


    if os.path.isfile(pkl_name):
        with open(pkl_name, 'rb') as input_pkl:
            result = pickle.load(input_pkl)
    else:
        if not os.path.isfile(out_csv):
            # Run destination analysis if necessary
            in_csv = args.in_csv
            if in_csv == "":
                in_csv = args.fig_dir + "/" + company + "_tmp.csv"
                cmd = ("python3 %s -i %s -m %s -o %s -n %s"
                       % (software_location, dir_name, mac, in_csv, args.num_proc))
                print("Running destination analysis...\n   " + cmd)
                os.system(cmd + " > /dev/null")

            # characterize the parties
            print("Characterizing the parties...")
            result = idtpt.run_extract_third_parties(in_csv, c.SCRIPT_DIR, company)

            # check if the traffic is encrypted
            print("Analyzing traffic encryption...")

            # result is a list of DestinationPro that
            # contains all the info
            result = ptals.run(dir_name=dir_name,
                               device_mac=mac,
                               script_dir=c.SCRIPT_DIR,
                               previous_info=result,
                               num_proc=int(args.num_proc))

            # check if the traffic is sent abroad
            print("Analyzing abroad traffic...")
            result = dtf_ab_adr.read_dst_csv_after_ping(pre_results=result,
                                                        dir_path=args.fig_dir,
                                                        company=company,
                                                        script_path=c.SCRIPT_DIR)

            save_object(result, pkl_name)

            # write the result to a csv file
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

            print("Results written to \"" + out_csv + "\"")

        else:
            # check if the traffic is sent abroad
            print("Analyzing abroad traffic...")
            result = dtf_ab_adr.read_dst_csv_after_ping(pre_results=out_csv,
                                                        dir_path=args.fig_dir,
                                                        company=company,
                                                        script_path=c.SCRIPT_DIR)
            save_object(result, pkl_name)

    # analyze the percentage of each party in all hosts and the amount of traffic
    # sent to each party, and generate the plots
    if dst_types != [""] and plot_types != [""]:
        print("Calculating party percentages and generating plots...")
        vis.calc_party_pct(csv_filename=out_csv, company=company, fig_dir=args.fig_dir,
                           fig_dpi=int(args.dpi), dst_types=dst_types, plot_types=plot_types,
                           linear=args.linear)

        # analyze the protocol and ports use; calculate the amount of traffic sent to
        # each destination and protocols, and visualizing the results as plots
        print("Calculating protocol percentages for encryption analysis and generating plots...")
        vis_pro.calc_encrypted_dst_pct(previous_data=result, company=company,
                                       fig_dir=args.fig_dir, fig_dpi=int(args.dpi),
                                       dst_types=dst_types, plot_types=plot_types,
                                       linear=args.linear)

        # analyze the country each destination is located in; calculate the amount of traffic
        # sent and visualize the results as plots
        print("Calculating country percentages for abroad analysis and generating plots...")
        vis_abr.run(previous_data=result, company=company,
                    fig_dir=args.fig_dir, fig_dpi=int(args.dpi),
                    dst_types=dst_types, plot_types=plot_types,
                    linear=args.linear)

    end_time = time.time()
    print("\nEnd time: %s" % time.strftime("%A %d %B %Y %H:%M:%S %Z", time.localtime(end_time)))

    # Calculate elapsed time
    sec = round(end_time - start_time)
    hrs = sec // 3600
    if hrs != 0:
        sec = sec - hrs * 3600

    minute = sec // 60
    if minute != 0:
        sec = sec - minute * 60

    print("Elapsed time: %s hours %s minutes %s seconds" % (hrs, minute, sec))

    print("\nAnalysis finished.")
