import csv

hosts_lists = ['amazon', 'google']
hosts_frequency = {'amazon': {}, 'google': {}}
file_list = ['dst_time_amazon.csv', 'dst_time_google.csv']
first_group = 'amazon'


def get_overlapping_hosts():
    host_frequency_dict = get_frequent_hosts(file_list=file_list)
    overlapping_set = set(host_frequency_dict[first_group].keys())
    for host in host_frequency_dict:
        overlapping_set = set(host_frequency_dict[host].keys()).intersection(overlapping_set)
    result_file = open('overlapping_hosts.txt', 'w+')
    for h in overlapping_set:
        result_file.write(h + '\n')


def calculate_frequency():
    host_frequency_dict = get_frequent_hosts(file_list=file_list)
    for host in hosts_lists:
        result_file = open('hosts_frequency_time_' + host + '.txt', 'w+')
        current_dict = host_frequency_dict[host]
        for h in current_dict:
            result_file.write(h + ':\n')
            for t in current_dict[h]:
                result_file.write(t + '\n')
            result_file.write("\n\n")


def get_frequent_hosts(file_list: list):
    index = 0
    for file in file_list:
        with open(file, mode='r', encoding='utf-8-sig') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                host = row['host']
                time = row['time']
                party = row['party']
                if party == "1" or party == "2":
                    current_dict = hosts_frequency[hosts_lists[index]]
                    if host in current_dict:
                        current_dict[host].add(time)
                    else:
                        current_dict[host] = set()
                        current_dict[host].add(time)
        index += 1
    return hosts_frequency
