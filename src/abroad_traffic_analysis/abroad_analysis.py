import json
import os
from subprocess import Popen, PIPE, STDOUT

#Output TXT file: IP, min_ping_time


def ping_ips(pre_results, dir_path, company, script_path):
    #Populate dict with non-local ip to country
    ip_ct = {}
    for dp in pre_results:
        if dp.host.party != "Local":
            ip_ct[dp.host.ip] = dp.host.country

    #Create country analysis directory
    country_ana_path = os.path.join(dir_path, "country_analysis")
    if not os.path.isdir(country_ana_path):
        os.system("mkdir -pv %s" % country_ana_path)

    #Write IPs to ping to a file so that it can be input for fping
    ping_result_file = os.path.join(dir_path, "country_analysis", company + "_ping_result.txt")
    with open(ping_result_file, "w") as f:
        f.write("\n".join(ip_ct.keys()))

    #Ping each unique non-local IP address using fping
    #fping sends a ping every 25 ms in the order of IPs in ping_result_file; will loop through file
    #5 times, meaning each IP pinged 5 times; timeout is 1 second; fping sends results to stderr
    ping_results = Popen("fping -i 25 -c 5 -q -f %s" % ping_result_file, shell=True, stdin=PIPE,
                         stdout=PIPE, stderr=STDOUT, close_fds=True).stdout.read().decode("utf-8")

    #The analysis - go through the ping results
    file_results = ""
    with open(os.path.join(script_path, "abroad_traffic_analysis/country_codes.json"), "r") as f:
        ct_dict = json.load(f)
    for result in ping_results.strip().split("\n"):
        result_words = result.split() #split line into words
        ip = result_words[0] #IP is 0th word in a line
        country = ip_ct[ip]
        if country.upper() in ("", " ", "N/A"):
            country = "XX"

        region = get_region(country.lower(), ct_dict) #get region of original country
        try:
            #use min time of the 5 pings as the ping time
            min_time = float(result_words[7].split("/")[0]) #min time left of first "/" in 7th word
            file_results += ip + "\t" + str(min_time) + " ms\n" #line to add to output file
        except IndexError:
            min_time = -999 #if timeout or can't ping, there is no 7th word in the line
            file_results += ip + "\tFAILED\n"

        #Determine if country needs to change, "n/a" means no change
        if country != "US" and region != "north america" and min_time != -999:
            if region in {"south america", "europe", "africa"} and min_time < 40:
               ip_ct[ip] = "US" 
            elif region == "middle east" and min_time < 60:
                ip_ct[ip] = "Likely US"
            elif region in {"asia", "oceania"} and min_time < 80:
                ip_ct[ip] = "Unknown"
            elif region == "n/a":
                if min_time < 40:
                    ip_ct[ip] = "US"
                elif min_time < 60:
                    ip_ct[ip] = "Likely US"
                else:
                    ip_ct[ip] = "Unknown"
            else:
                ip_ct[ip] = "n/a"
        else:
            ip_ct[ip] = "n/a"

    #Change the country if necessary
    for dp in pre_results:
        if dp.host.party != "Local" and ip_ct[dp.host.ip] != "n/a":
            dp.host.country = ip_ct[dp.host.ip]

    #Write the output file
    with open(ping_result_file, "w") as f:
        f.write(file_results.strip())
        print("Ping times written to \"%s\"" % ping_result_file)

    return pre_results

    
def get_region(ct_abbr, ct_dict):
    for ct_region in ct_dict:
        if ct_abbr in ct_dict[ct_region]:
            return ct_region
    return "n/a"

