import csv
import re
# github for adblock parser: https://github.com/scrapinghub/adblockparser
# pip install adblockparser
import adblockparser

from subprocess import check_output
import subprocess

options = ('device', 'ip', 'host', 'host_full', 'traffic_snd',
           'traffic_rcv', 'packet_snd', 'packet_rcv', 'country',
           'party', 'lab', 'experiment', 'network', 'input_file',
           'organization')
company_list = ['amazon', 'google']
party_dict = {"-2": "Physical", "-1": "Local",
              "0": "First party", "1": "Support party",
              "2": "Third party", "2.5": "Advertisers",
              "3": "Analytics"}
company_name_dict = {"google": "Google LLC", "amazon": "Amazon.com Inc."}


# find all the third parties in the list of pcap
# files and write them to a txt file
def run_extract_third_parties(input_csv_file, script_dir, company="unknown"):
    all_ads = set()

    # fina all the third parties using
    # the csv file we have
    all_ads.union(find_third_party_using_given_csv(input_csv_file, script_dir))

    # read each line from the input csv file
    result = {key: list() for key in options}
    max_host = ''
    with open(file=input_csv_file, mode='r', encoding='utf-8-sig') as input_file:
        csv_reader = csv.DictReader(input_file)
        host_traffic_received = {}
        max_traffic = 0
        for row in csv_reader:

            # get the host that received the most traffic
            host = row['host']
            traffic_rcv = int(row['traffic_rcv'])
            total_t: int
            if host in host_traffic_received:
                total_t = host_traffic_received[host] + traffic_rcv
            else:
                total_t = traffic_rcv
            host_traffic_received[host] = total_t
            if total_t > max_traffic:
                max_host = host
                max_traffic = total_t

            # read all the info in the input csv file
            index = 0
            while index < options.__len__():
                title = options[index]
                result[title].append(row[title])
                index += 1

    general_party_info = {'0': set(),
                          '1': set(),
                          '2': set(),
                          '2.5': set(),
                          '3': set(),
                          '-1': set(),
                          '-2': set()}

    # for support party: (Cloud Computing Services AWS and
    # Google Cloud, Azure ...), CDN service, DNS service
    # for advertisers: from previous results and EasyList
    # for analytics: data analytics
    file1 = open(script_dir + "/dst_characterize/general_ad_support_party.txt", 'r')
    current_party = ''
    for line in file1:
        party = line.split()[0]
        if party in ['1', '2.5', '3']:
            current_party = party
            continue
        else:
            general_party_info[current_party].add(line.split("\n")[0])

    general_party_info['2.5'].union(all_ads)

    # if the user does not provide the first party company,
    # then we assume it's whoever received the most traffic
    if company == 'unknown':
        company = max_host.split('.')[0]

    host_list = result['host']
    for c in company_list:
        if c in company:
            # add first party info and delete incorrect support party
            # (we only have data from device whose companies
            # are Amazon and Google for now)
            general_party_info = read_party_info(filename=script_dir + '/dst_characterize/unique_sld_' + c,
                                                 party_info=general_party_info)

    # hosts that contain the first party name are
    # most likely (could be not accurate) the first parties
    for h in host_list:
        if company in h:
            general_party_info['0'].add(h)

    index = 0
    host_org = {}
    for host in host_list:
        party = identify_party(host=host, party_info=general_party_info)
        if party != "no party":
            result['party'][index] = party_dict[party]
        # detect local traffic
        elif detect_local_host(host):
            result['party'][index] = 'Local'
        # detect physical traffic
        elif detect_physical_host(host):
            result['party'][index] = 'Physical'
        # the left are third party
        else:
            result['party'][index] = 'Third party'

        # add or update the organization/company of the host
        new_party = result['party'][index]
        # if it's a first party and the first party is amazon and google,
        # we already know the name of the org
        if new_party == 'First party' and company in company_name_dict:
            result['organization'][index] = company_name_dict[company]
        elif new_party != 'Local' and new_party != 'Physical':
            try:
                org = ""
                if host in host_org:  # use organization in dict if host exists in the dict
                    org = host_org[host]
                else:  # get organzation using whois and save host/org to dict
                    org = get_org_using_who_is_server(host)
                    host_org[host] = org

                org = org.lower()
                # if it is amazon or google
                if company in org and company in company_name_dict:
                    result['organization'][index] = company_name_dict[company]
                # if the org is empty, use the sld
                elif org == "" or org == " " or org == "n/a" \
                        or org.upper() == "REDACTED FOR PRIVACY":
                    result['organization'][index] = host.split(".")[0].capitalize()
                # else, use the org
                else:
                    org = org.split(", ")[0]
                    result['organization'][index] = org.capitalize()
            except subprocess.CalledProcessError:
                result['organization'][index] = host.split(".")[0].capitalize()
        index += 1
    return result


# get the org of a host/IP by using who is
# server to get its SLD
def get_org_using_who_is_server(host):
    who_is_answer = check_output(['whois', host])
    ls: str = who_is_answer.decode("utf-8")
    ls: list = ls.splitlines()
    org = ""
    for s in ls:
        if s.startswith("Registrant Organization: "):
            org = s[25:]
            break

    return org


# for detect a valid mac address, must use separator ":" or "-"
def detect_physical_host(host: str):
    match_pattern = '^[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$'
    return re.search(match_pattern, host.lower())


# for detecting IPv4
def detect_local_host(host: str):
    match_pattern = '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
    match_pattern = '(' + match_pattern + '.)' + '{3}' + match_pattern
    match_pattern = '^(' + match_pattern + ')$'
    if "." in host:
        host_list = host.split(".")
        return host_list.__len__() == 4 and re.search(match_pattern, host)
    else:
        return False


def identify_party(host, party_info):
    for party in party_info:
        if host in party_info[party]:
            return party
    return "no party"


def read_party_info(filename, party_info):
    file = open(filename + '.txt', 'r')
    for line in file:
        line = line.split("\n")[0]
        party_info['0'].add(line)
        party_info['1'].discard(line)
    return party_info


def find_third_party_using_given_csv(csv_file, script_dir):
    ad_rules = []
    with open(script_dir + '/dst_characterize/easylist_adblock.txt', 'r') as f:
        ad_rules = adblockparser.AdblockRules(f.readlines())

    ad_list = set()

    with open(csv_file, mode="r") as csv_file1:
        csv_reader = csv.DictReader(csv_file1)
        visited_domains = []  # don't need to run domains through ad rules more than once
        for row in csv_reader:
            current_domain: str = row[options[3]]
            if current_domain not in visited_domains:
                visited_domains.append(current_domain)
                current_domain_full = "http://" + current_domain + "/"
                if ad_rules.should_block(current_domain_full):
                    ad_list.add(current_domain)
                else:
                    current_domain_full = "https://" + current_domain + "/"
                    if ad_rules.should_block(current_domain_full):
                        ad_list.add(current_domain)
                        
    return ad_list

