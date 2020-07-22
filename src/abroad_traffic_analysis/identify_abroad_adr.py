import pythonping as ping
from dst_characterize import identify_party as dtf_pt
from party_analysis import visualization_parties as vis_p
import json, pandas as pd
from protocol_analysis import Destination, DestinationPro
from protocol_analysis import protocol_analysis as pa

from protocol_analysis import ProtocolPort
from multiprocessing import Process
from multiprocessing import Manager
import time

protocol_details = {"Https": "TCP port: 443", "Http": "TCP port: 80"}

# need to install pythonping packet (pip install pythonping)
# https://pypi.org/project/pythonping/
def read_dst_csv_after_ping(pre_results, dir_path, company, script_path):
    dir_path = vis_p.check_dir_exist(ori_path=dir_path,
                                     new_dir="country_analysis")
    ping_result_file = open(dir_path + "/" + company + "_ping_result.txt", "w+")
    ct_dict = read_json_ct(script_path + "/"
                           + "abroad_traffic_analysis/country_codes.json")

    #get dict of unique ip addresses along with initial country
    ip_ct = Manager().dict()
    for dp in pre_results:
        ip_ct[dp.host.ip] = dp.host.country

    #make a ping every 0.5 sec
    procs = []
    file_results = Manager().list()
    for ip in ip_ct.keys():
        p = Process(target=run_pings, args=(ip, ip_ct, ct_dict, file_results))
        procs.append(p)
        p.start()
        time.sleep(0.5)

    for p in procs:
        p.join()

    for dp in pre_results:
        if ip_ct[dp.host.ip] != "n/a":
            dp.host.country = ip_ct[dp.host.ip]

    ping_result_file.write("".join(file_results))
    return pre_results


def run_pings(ip, ip_ct, ct_dict, file_results):
    ip_ct[ip] = confirm_country(ip, ip_ct[ip], ct_dict, file_results)


def confirm_country(ip, country, ct_dict, file_results):
    if not dtf_pt.detect_local_host(host=country):
        if country.upper() in {"", " ", "N/A"}:
            country = "XX"

        region = get_region(ct_abbr=country.lower(), ct_dict=ct_dict)

        # get the avg response time in ms
        mean_ping_ms = ping_host(ip)

        # write the average round-trip ping time to a txt file
        file_results.append(ip + " ping round-trip: "
                               + str(mean_ping_ms) + " ms"
                               + "\n")

        # check the country for each address based
        # on previous data and ping result
        if country != "US" and region != "north america" and mean_ping_ms != -999:
            if region in {"south america", "europe", "africa"} and mean_ping_ms < 40:
                return "US"
            elif region == "middle east" and mean_ping_ms < 60:
                return "Likely US"
            elif region in {"asia", "oceania"} and mean_ping_ms < 80:
                return "Unknown"
            elif region == "n/a":
                if mean_ping_ms < 40:
                    return "US"
                elif mean_ping_ms < 60:
                    return "Likely US"
                else:
                    return "Unknown"
    return "n/a"


def get_region(ct_abbr, ct_dict):
    for ct_region in ct_dict:
       if ct_abbr in ct_dict[ct_region]:
             return ct_region
    return "n/a"


# ping a host and get the avg round-trip response
# time in ms
def ping_host(ip_adr):
    test_list = ping.ping(target=ip_adr,
                          count=5,
                          timeout=1)
    if all(map(lambda x: str(x) == "Request timed out",
               test_list)):
        return -999
    else:
        res_list = ping.ping(target=ip_adr,
                             count=20)
        return res_list.rtt_avg_ms


def read_json_ct(file_path):
    with open(file_path) as f:
        ct_dict = json.load(f)
        f.close()
        return ct_dict

