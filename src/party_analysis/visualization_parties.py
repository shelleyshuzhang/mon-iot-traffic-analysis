import csv
import numpy as np
from party_analysis import pie_related_plots as prp
from party_analysis import bar_related_plots as brp

party_name_dict = {"-1": "Local", "0": "First party",
                   "1": "Support party", "2": "Third party",
                   "2.5": "Advertiser", "3": "Analytics"}
party_color_dict = {"0": 'Reds', "1": 'Blues', "2": "Greens",
                    "3": "Purples", "4": "Oranges", "5": "Greys"}
party_bar_dict = {"First party": "0",
                  "Support party": "1",
                  "Third party": "2",
                  "Local": "3",
                  "Advertisers": "4",
                  "Analytics": "5"}
party_index_dict = {"Physical": "-2", "Local": "-1",
                    "First party": "0", "Support party": "1",
                    "Third party": "2", "Advertisers": "2.5",
                    "Analytics": "3"}
host_name_too_long = {"0": 'other first party',
                      "1": 'other support party',
                      "2": 'other third party',
                      "-1": 'other local party',
                      "2.5": 'other advertisers',
                      "3": 'other analytics'}


def calculate_party_percentage(csv_filename: str, company: str,
                               fig_dir: str, dst_type: str,
                               plot_type: str):
    party_sld_traffic = {"0": {}, "1": {}, "2": {},
                         "-1": {}, "2.5": {}, "3": {}}
    party_fqdn_traffic = {"0": {}, "1": {}, "2": {},
                          "-1": {}, "2.5": {}, "3": {}}
    party_org_traffic = {"0": {}, "1": {}, "2": {},
                         "-1": {}, "2.5": {}, "3": {}}
    with open(csv_filename, mode="r") as csv_file1:
        csv_reader = csv.DictReader(csv_file1)

        for row in csv_reader:
            current_domain_sld: str = row['host']
            current_domain_fqdn: str = row['host_full']
            current_domain_org: str = row['organization']
            current_party = row['party']
            current_party = party_index_dict[current_party]
            size = int(row['packet_rcv'])

            if current_party != "-2":
                if current_domain_sld in party_sld_traffic[current_party]:
                    party_sld_traffic[current_party][current_domain_sld] += size
                else:
                    party_sld_traffic[current_party][current_domain_sld] = size

                if current_domain_fqdn in party_fqdn_traffic[current_party]:
                    party_fqdn_traffic[current_party][current_domain_fqdn] += size
                else:
                    party_fqdn_traffic[current_party][current_domain_fqdn] = size

                if current_domain_org in party_org_traffic[current_party]:
                    party_org_traffic[current_party][current_domain_org] += size
                else:
                    party_org_traffic[current_party][current_domain_org] = size

    if plot_type == "PiePlot":
        if dst_type == "sld":
            # plot the percentage of different parties - destinations(SLD)
            prp.pie_plot_percentage(party_dict=party_sld_traffic,
                                    title="The percentage of first, support and "
                                          "third parties in all destination SLDs ("
                                          + company + " device)",
                                    save_name=fig_dir + "/" + company
                                              + "_device_party_SLDs_pie.png",
                                    name_dict=party_name_dict)

            # write all the sld by party for the device
            sld_filename = fig_dir + "/" + company + "_all_sld.txt"
            write_hosts_by_party(party_dict=party_sld_traffic, fname=sld_filename)
            print("    Second level domains written to \"" + sld_filename + "\"")

            # plot traffic sent to different parties - destinations(SLD)
            for p in party_bar_dict:
                index = party_index_dict[p]
                if party_sld_traffic[index].__len__() != 0:
                    prp.plot_traffic_dst(party_hosts_traffic=party_sld_traffic,
                                         party_bar_plot=party_bar_dict[p],
                                         save_name=fig_dir + "/" + company + "_"
                                                   + p.split()[0] + "_party_SLD_traffic_pie.png",
                                         title="The percentage of traffic sent "
                                               "to each destination SLD ("
                                               + company + " device/in bytes)",
                                         name_dict=party_name_dict,
                                         third_party_color=party_color_dict[party_bar_dict[p]],
                                         host_name_too_long=host_name_too_long,
                                         fig_h=20,
                                         fig_w=14,
                                         fond_s=18)
        elif dst_type == "fqdn":
            # plot the percentage of different parties - destinations(FQDN)
            prp.pie_plot_percentage(party_dict=party_fqdn_traffic,
                                    title="The percentage of first, support and "
                                          "third parties in all destination FQDNs ("
                                          + company + " device)",
                                    save_name=fig_dir + "/" + company
                                              + "_device_party_FQDNs_pie.png",
                                    name_dict=party_name_dict)

            # write all the FQDN by party for the device
            fqdn_filename = fig_dir + "/" + company + "_all_fqdn.txt"
            write_hosts_by_party(party_dict=party_fqdn_traffic, fname=fqdn_filename)
            print("    Fully qualified domains written to \"" + fqdn_filename + "\"")

            # plot traffic sent to different parties - destinations(FQDN)
            for p in party_bar_dict:
                index = party_index_dict[p]
                if party_fqdn_traffic[index].__len__() != 0:
                    prp.plot_traffic_dst(party_hosts_traffic=party_fqdn_traffic,
                                         party_bar_plot=party_bar_dict[p],
                                         save_name=fig_dir + "/" + company + "_"
                                                   + p.split()[0]
                                                   + "_party_FQDN_traffic_pie.png",
                                         title="The percentage of traffic sent "
                                               "to each destination FQDN ("
                                               + company + " device/in bytes)",
                                         name_dict=party_name_dict,
                                         third_party_color=party_color_dict[party_bar_dict[p]],
                                         host_name_too_long=host_name_too_long,
                                         fig_h=23,
                                         fig_w=16,
                                         fond_s=15)
        elif dst_type == "org":
            # plot the percentage of different parties - organizations(ORG)
            prp.pie_plot_percentage(party_dict=party_org_traffic,
                                    title="The percentage of first, support and "
                                          "third parties in all destination Organizations ("
                                          + company + " device)",
                                    save_name=fig_dir + "/" + company
                                              + "_device_party_ORGs_pie.png",
                                    name_dict=party_name_dict)

            # write all the ORGs by party for the device
            org_filename = fig_dir + "/" + company + "_all_org.txt"
            write_hosts_by_party(party_dict=party_org_traffic, fname=org_filename)
            print("    Organizations written to \"" + org_filename + "\"")

            # plot traffic sent to different parties - destinations(ORG)
            for p in party_bar_dict:
                index = party_index_dict[p]
                if party_org_traffic[index].__len__() != 0:
                    prp.plot_traffic_dst(party_hosts_traffic=party_org_traffic,
                                         party_bar_plot=party_bar_dict[p],
                                         save_name=fig_dir + "/" + company + "_"
                                                   + p.split()[0]
                                                   + "_party_ORG_traffic_pie.png",
                                         title="The percentage of traffic sent "
                                               "to each destination ORG ("
                                               + company + " device/in bytes)",
                                         name_dict=party_name_dict,
                                         third_party_color=party_color_dict[party_bar_dict[p]],
                                         host_name_too_long=host_name_too_long,
                                         fig_h=20,
                                         fig_w=14,
                                         fond_s=18)
    elif plot_type == "BarHPlot":
        if dst_type == "sld":
            # plot traffic sent to different parties - destinations(SLD)
            for p in party_bar_dict:
                index = party_index_dict[p]
                all_hosts = party_sld_traffic[index]
                party_name = party_index_dict[p]
                if all_hosts.__len__() != 0:
                    other_h_t = 0
                    too_small_h = []
                    for host in all_hosts:
                        current_t = all_hosts[host]
                        all_hosts_len = all_hosts.__len__()
                        all_t = int(np.array(list(all_hosts.values())).sum())
                        if all_hosts_len > 20 and \
                                ((p != "Advertiser" and current_t / all_t <= 0.002)
                                 or (p == "Advertiser" and current_t / all_t <= 0.0001)):
                            other_h_t += current_t
                            too_small_h.append(host)
                    if other_h_t > 0:
                        all_hosts[host_name_too_long[party_name]] = other_h_t
                        for h in too_small_h:
                            del all_hosts[h]
                    brp.bar_plot_horizontal(data=list(all_hosts.values()),
                                            names=list(all_hosts.keys()),
                                            height=24,
                                            wide=18,
                                            title="The percentage of traffic sent "
                                                  "to each destination SLD (" +
                                                  company + "/" + p + ")",
                                            color_p=party_color_dict[party_bar_dict[p]],
                                            num_name="Amount of traffic (Bytes)",
                                            save_name=fig_dir + "/" + company + "_"
                                                      + p.split()[0]
                                                      + "_party_SLD_traffic_bar.png")
        elif dst_type == "fqdn":
            # plot traffic sent to different parties - destinations(FQDN)
            for p in party_bar_dict:
                index = party_index_dict[p]
                all_hosts = party_fqdn_traffic[index]
                party_name = party_index_dict[p]
                if all_hosts.__len__() != 0:
                    other_h_t = 0
                    too_small_h = []
                    for host in all_hosts:
                        current_t = all_hosts[host]
                        all_hosts_len = all_hosts.__len__()
                        all_t = int(np.array(list(all_hosts.values())).sum())
                        if all_hosts_len > 20 and \
                                ((p != "Advertiser" and current_t / all_t <= 0.00005)
                                 or (p == "Advertiser" and current_t / all_t <= 0.0001)):
                            other_h_t += current_t
                            too_small_h.append(host)
                    if other_h_t > 0:
                        all_hosts[host_name_too_long[party_name]] = other_h_t
                        for h in too_small_h:
                            del all_hosts[h]
                    brp.bar_plot_horizontal(data=list(all_hosts.values()),
                                            names=list(all_hosts.keys()),
                                            height=24,
                                            wide=18,
                                            title="The percentage of traffic sent "
                                                  "to each destination FQDN (" +
                                                  company + "/" + p + ")",
                                            color_p=party_color_dict[party_bar_dict[p]],
                                            num_name="Amount of traffic (Bytes)",
                                            save_name=fig_dir + "/" + company + "_"
                                                      + p.split()[0]
                                                      + "_party_FQDN_traffic_bar.png")
        elif dst_type == "org":
            # plot traffic sent to different parties - destinations(ORG)
            for p in party_bar_dict:
                index = party_index_dict[p]
                all_hosts = party_org_traffic[index]
                party_name = party_index_dict[p]
                if all_hosts.__len__() != 0:
                    other_h_t = 0
                    too_small_h = []
                    for host in all_hosts:
                        current_t = all_hosts[host]
                        all_hosts_len = all_hosts.__len__()
                        all_t = int(np.array(list(all_hosts.values())).sum())
                        if all_hosts_len > 20 and \
                                ((p != "Advertiser" and current_t / all_t <= 0.002)
                                 or (p == "Advertiser" and current_t / all_t <= 0.0001)):
                            other_h_t += current_t
                            too_small_h.append(host)
                    if other_h_t > 0:
                        all_hosts[host_name_too_long[party_name]] = other_h_t
                        for h in too_small_h:
                            del all_hosts[h]
                    brp.bar_plot_horizontal(data=list(all_hosts.values()),
                                            names=list(all_hosts.keys()),
                                            height=24,
                                            wide=18,
                                            title="The percentage of traffic sent "
                                                  "to each destination ORG (" +
                                                  company + "/" + p + ")",
                                            color_p=party_color_dict[party_bar_dict[p]],
                                            num_name="Amount of traffic (Bytes)",
                                            save_name=fig_dir + "/" + company
                                                      + "_" + p.split()[0]
                                                      + "_party_ORG_traffic_bar.png")


def write_hosts_by_party(party_dict, fname):
    with open(fname, "w+") as f:
        for p in party_dict:
            f.write(p + " party dst:\n")
            for sld in party_dict[p]:
                f.write(sld + "\n")
