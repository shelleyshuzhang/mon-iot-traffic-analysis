import pythonping as ping
from dst_characterize import identify_party as dtf_pt
from party_analysis import visualization_parties as vis_p
import json, pandas as pd
from protocol_analysis import Destination, DestinationPro
from protocol_analysis import protocol_analysis as pa

from protocol_analysis import ProtocolPort

protocol_details = {"Https": "TCP port: 443", "Http": "TCP port: 80"}


# need to install pythonping packet (pip install pythonping)
# https://pypi.org/project/pythonping/
def read_dst_csv_after_ping(pre_results, dir_path, company, script_path):
    dir_path = vis_p.check_dir_exist(ori_path=dir_path,
                                     new_dir="country_analysis")
    ping_result_file = open(dir_path + "/" + company + "_ping_result.txt", "w+")
    ct_dict = read_json_ct(script_path + "/"
                           + "abroad_traffic_analysis/country_codes.json")

    def get_region(ct_abbr):
        for ct_region in ct_dict:
            if ct_abbr in ct_dict[ct_region]:
                return ct_region
        return "n/a"

    # ping harvard university to get
    # the base respond time, assuming
    # our student will use this
    # in US
    base_time = ping_host("harvard.edu")
    if base_time == -1:
        base_time = 15

    if isinstance(pre_results, str):
        results = []
        pa.read_protocol_csv(script_path + "/protocol_analysis/protocols_info.csv")
        all_dp = pd.read_csv(pre_results, dtype=str)
        all_dp.fillna("n/a")
        dp_rows = all_dp.shape[0]
        index = 0
        while index < dp_rows:
            confirmed_ct = confirm_country(ip=all_dp["ip"][index],
                                           country=all_dp["country"][index],
                                           get_region=get_region,
                                           base_time=base_time,
                                           ping_result_file=ping_result_file)
            if confirmed_ct != "n/a":
                all_dp["country"][index] = confirmed_ct

            current_dst = Destination.Destination(host=all_dp['host'][index],
                                                  party=all_dp['party'][index],
                                                  ip=all_dp['ip'][index],
                                                  host_full=all_dp['host_full'][index],
                                                  country=all_dp['country'][index],
                                                  org=all_dp['organization'][index])
            protocol_port = all_dp['protocol&port'][index]
            if protocol_port in protocol_details:
                protocol_port = protocol_details[protocol_port]
            if protocol_port in pa.protocol_info:
                current_pro = pa.protocol_info[protocol_port]
            else:
                current_pro = ProtocolPort.ProtocolPort(protocol_port, '-1', '-1', '-1', '-1')
            current_dst_pro = DestinationPro.DestinationPro(dst=current_dst,
                                                            pro_port=current_pro)
            current_dst_pro.add_all(snd_traf=int(all_dp['traffic_snd'][index]),
                                    rcv_traf=int(all_dp['traffic_rcv'][index]),
                                    pak_num_snd=int(all_dp['packet_snd'][index]),
                                    pak_num_rcv=int(all_dp['packet_rcv'][index]))
            results.append(current_dst_pro)
            index += 1

        ping_result_file.close()
        all_dp.to_csv(pre_results, index=False)
        return results
    elif isinstance(pre_results, list):
        previous_ips = {}
        for dp in pre_results:
            dst = dp.host
            ip = dst.ip
            if ip not in previous_ips.keys():
                country = dst.country
                confirmed_ct = confirm_country(ip=ip,
                                               country=country,
                                               get_region=get_region,
                                               base_time=base_time,
                                               ping_result_file=ping_result_file)
                previous_ips[ip] = confirmed_ct
                print(ip, confirmed_ct)
            else:
                print(ip, previous_ips[ip], "prev")

            if previous_ips[ip] != "n/a":
                dp.country = previous_ips[ip]

        return pre_results


def confirm_country(ip, country, get_region, base_time,
                    ping_result_file):
    if not dtf_pt.detect_local_host(host=country):
        if country == "" or country == " " \
                or country.upper() == "N/A":
            country = "XX"
        region = get_region(ct_abbr=country.lower())

        # get the avg response time in ms
        mean_ping_ms = ping_host(ip)
        if mean_ping_ms != -1:
            mean_ping_ms -= base_time

        # write the average round-trip ping time to a txt file
        ping_result_file.write(ip + " ping round-trip: "
                               + str(mean_ping_ms) + " ms"
                               + "\n")

        # check the country for each address based
        # on previous data and ping result
        if country != "US" and region != "north america":
            if (region == "south america"
                or region == "europe"
                or region == "africa") and mean_ping_ms < 40:
                return "US"
            elif region == "middle east" and mean_ping_ms < 60:
                return "Likely US"
            elif (region == "asia"
                  or region == "oceania") and mean_ping_ms < 80:
                return "Unknown"
            elif region == "n/a":
                if mean_ping_ms < 40:
                    return "US"
                elif mean_ping_ms < 60:
                    return "Likely US"
                else:
                    return "Unknown"
    return "n/a"


# ping a host and get the avg round-trip response
# time in ms
def ping_host(ip_adr):
    test_list = ping.ping(target=ip_adr,
                          count=5,
                          timeout=1)
    if all(map(lambda x: str(x) == "Request timed out",
               test_list)):
        return -1
    else:
        res_list = ping.ping(target=ip_adr,
                             count=20)
        return res_list.rtt_avg_ms


def read_json_ct(file_path):
    with open(file_path) as f:
        ct_dict = json.load(f)
        f.close()
        return ct_dict

