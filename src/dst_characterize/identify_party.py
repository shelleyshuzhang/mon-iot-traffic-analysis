import csv
import re
import os

# github for adblock parser: https://github.com/scrapinghub/adblockparser
# pip install adblockparser
import adblockparser

options = ('device', 'ip', 'host', 'host_full', 'traffic_snd',
           'traffic_rcv', 'packet_snd', 'packet_rcv', 'country',
           'party', 'lab', 'experiment', 'network', 'input_file',
           'organization')
company_list = ['amazon', 'google']
party_dict = {"-2": "Physical", "-1": "Local",
              "0": "First party", "1": "Support party",
              "2": "Third party", "2.5": "Advertisers",
              "3": "Unknown"}


# find all the third parties in the list of pcap
# files and write them to a txt file
def run_extract_third_parties(input_csv_file, script_dir, out_csv, company="unknown"):
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
    file1 = open(script_dir + "/dst_characterize/general_ad_support_party.txt", 'r')
    current_party = ''
    for line in file1:
        party = line.split()[0]
        if party in ['1', '2.5']:
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
    if company in company_list:
        # add first party info and delete incorrect support party
        # (we only have data from device whose companies
        # are Amazon and Google for now)
        general_party_info = read_party_info(filename=script_dir + '/dst_characterize/unique_sld_' + company, party_info=general_party_info)
    # hosts that contain the first party name are
    # most likely (could be not accurate) the first parties
    for h in host_list:
        if company in h:
            general_party_info['0'].add(h)

    index = 0
    for host in host_list:
        party = identify_party(host=host, party_info=general_party_info)
        if party != "no party":
            result['party'][index] = party_dict[party]
        elif re.match(r"\d\d\d.\d\d\d.\d\d\d.\d\d\d", host):
            result['party'][index] = 'Local'
        elif ":" in host:
            result['party'][index] = 'Physical'
        else:
            result['party'][index] = 'Third party'
        index += 1

    out_csv_dir = os.path.dirname(out_csv)
    if out_csv_dir != "" and not os.path.isdir(out_csv_dir):
        os.system("mkdir -pv " + out_csv_dir)

    with open(file=out_csv, mode='w') as result_csv_file:
        fieldnames = ('ip', 'host', 'host_full', 'traffic_snd',
                      'traffic_rcv', 'packet_snd', 'packet_rcv', 'country',
                      'party', 'input_file', 'organization')
        writer = csv.DictWriter(result_csv_file, fieldnames=fieldnames)
        writer.writeheader()
        total_num = result['ip'].__len__()
        index = 0
        while index < total_num:
            writer.writerow({'ip': result['ip'][index],
                             'host': result['host'][index],
                             'host_full': result['host_full'][index],
                             'traffic_snd': result['traffic_snd'][index],
                             'traffic_rcv': result['traffic_rcv'][index],
                             'packet_snd': result['packet_snd'][index],
                             'packet_rcv': result['packet_rcv'][index],
                             'country': result['country'][index],
                             'party': result['party'][index],
                             'input_file': result['input_file'][index],
                             'organization': result['organization'][index]})
            index += 1

    print("Results written to \"" + out_csv + "\"")


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
    file = open(script_dir + '/dst_characterize/easylist_adblock.txt', 'r')
    filters = []
    for line in file:
        filters.append(line)
    ad_rules = adblockparser.AdblockRules(filters)

    ad_list = set()

    with open(csv_file, mode="r") as csv_file1:
        csv_reader = csv.DictReader(csv_file1)
        for row in csv_reader:
            current_domain: str = row[options[3]]
            current_domain_full = "http://" + current_domain + "/"
            if ad_rules.should_block(current_domain_full):
                ad_list.add(current_domain)
            else:
                current_domain_full = "https://" + current_domain + "/"
                if ad_rules.should_block(current_domain_full):
                    ad_list.add(current_domain)
    return ad_list
