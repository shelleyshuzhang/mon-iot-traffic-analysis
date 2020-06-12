import pythonping as ping
from dst_characterize import identify_party as dtf_pt
from party_analysis import visualization_parties as vis_p


def read_dst_csv_after_ping(result, dir_path, company):
    dir_path = vis_p.check_dir_exist(ori_path=dir_path,
                                     new_dir="country_analysis")
    ping_result_file = open(dir_path + "/" + company + "_ping_result.txt", "w+")

    for dp in result:
        dst = dp.host
        ip = dst.ip
        country = dst.country

        if dtf_pt.detect_local_host(host=country):
            dst.country = "Local"
        else:
            if country == "" or country == " " \
                    or country.upper() == "N/A":
                country = "XX"

            # get the avg response time in ms
            mean_ping_ms = ping_host(ip)

            # check the country for each address based
            # on previous data and ping result
            if mean_ping_ms == -1:
                dst.country = "Unknown - ping timeout"
            elif 0 <= mean_ping_ms < 50:
                if country != "US":
                    dst.country = "Unknown - likely US"
            elif mean_ping_ms >= 50:
                if country == "US" or country == "XX":
                    dst.country = "Unknown - likely abroad"

            # write the average round-trip ping time to a txt file
            ping_result_file.write(ip + " ping round-trip: "
                                   + str(mean_ping_ms) + " ms"
                                   + "\n")

    ping_result_file.close()
    return result


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
