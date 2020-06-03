import csv
import os

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
dst_type_name_dict = {"SLD": "Second level domain",
                      "FQDN": "Fully qualified domain",
                      "ORG": "Organization"}
patch_dict = {"0": '0',
              "1": '1',
              "2": '2',
              "3": '-1',
              "4": '2.5',
              "5": '3'}


def calculate_party_percentage(csv_filename: str, company: str,
                               fig_dir: str, dst_types: list,
                               plot_types: list, linear: bool):
    party_sld_traffic = {"0": {}, "1": {}, "2": {},
                         "-1": {}, "2.5": {}, "3": {}}
    party_fqdn_traffic = {"0": {}, "1": {}, "2": {},
                          "-1": {}, "2.5": {}, "3": {}}
    party_org_traffic = {"0": {}, "1": {}, "2": {},
                         "-1": {}, "2.5": {}, "3": {}}

    fig_dir = check_dir_exist(fig_dir, "dst_party_analysis")

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

    def make_pie_plot(dst_type_name, party_t_dict, fig_h, fig_w, fond_s, pie_fig_dir):
        pie_fig_dir = check_dir_exist(pie_fig_dir, "pie")
        pie_fig_dir = check_dir_exist(pie_fig_dir, dst_type_name)
        dst_type_name = dst_type_name.upper()
        # plot the percentage of different parties - destinations
        prp.pie_plot_percentage(party_dict=party_t_dict,
                                title="The percentage of first, support and "
                                      "third parties in all destination "
                                      + dst_type_name + "s (" + company + " device)",
                                save_name=pie_fig_dir + "/" + company
                                          + "_device_parties_pie_"
                                          + dst_type_name + ".png",
                                name_dict=party_name_dict)

        # write all the dst by party for the device
        dst_filename = pie_fig_dir + "/" + company + "_all_" + dst_type_name + ".txt"
        write_hosts_by_party(party_dict=party_t_dict, fname=dst_filename)
        print("    " + dst_type_name_dict[dst_type_name]
              + "s written to \"" + dst_filename + "\"")

        # plot traffic sent to different parties - destinations
        for p in party_bar_dict:
            p1 = ''
            if p == "Support party" or p == "Analytics" or p == "Advertisers":
                continue
            else:
                if p == "First party":
                    p1 = "Support party"
                elif p == "Third party":
                    p1 = "Advertisers"
                elif p == "Local":
                    p1 = "Analytics"
            index1 = party_index_dict[p]
            index2 = party_index_dict[p1]
            non_data1 = party_t_dict[index1].__len__() == 0
            non_data2 = party_t_dict[index2].__len__() == 0
            if not non_data1 or not non_data2:
                prp.plot_traffic_dst(party_hosts_traffic=party_t_dict,
                                     party_bar_plot=[party_bar_dict[p],
                                                     party_bar_dict[p1]],
                                     save_name=pie_fig_dir + "/" + company + "_pie_"
                                               + dst_type_name + "_" + p.split()[0]
                                               + "_" + p1.split()[0] + "_party_traffic.png",
                                     title="The percentage of traffic sent "
                                           "to each destination " + dst_type_name
                                           + " (" + company + " device/in bytes)",
                                     name_dict=party_name_dict,
                                     third_party_color=[party_color_dict[party_bar_dict[p]],
                                                        party_color_dict[party_bar_dict[p1]]],
                                     host_name_too_long=host_name_too_long,
                                     empty_parties=[non_data1, non_data2],
                                     fig_h=fig_h,
                                     fig_w=fig_w,
                                     fond_s=fond_s,
                                     patch_dict=patch_dict)

    def make_bar_h_plot(party_t_dict, dst_type_name, fig_h, fig_w, barh_fig_dir):
        barh_fig_dir = check_dir_exist(barh_fig_dir, "barH")
        barh_fig_dir = check_dir_exist(barh_fig_dir, dst_type_name)
        dst_type_name = dst_type_name.upper()
        # plot traffic sent to different parties - destinations
        for p in party_bar_dict:
            index = party_index_dict[p]
            all_hosts = party_t_dict[index]
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
                                        height=fig_h,
                                        wide=fig_w,
                                        title="The percentage of traffic sent "
                                              "to each destination " + dst_type_name
                                              + " (" + company + "/" + p + ")",
                                        color_p=party_color_dict[party_bar_dict[p]],
                                        num_name="Amount of traffic shown using "
                                                 "logarithmic scale (Bytes)",
                                        save_name=barh_fig_dir + "/" + company + "_bar_"
                                                  + dst_type_name + "_" + p.split()[0]
                                                  + "_party_traffic.png")

    def make_plot(input_plot_type: str, input_dst_type: str):
        if input_plot_type == "pieplot":
            if input_dst_type == "sld":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=party_sld_traffic,
                              fig_w=32,
                              fig_h=16,
                              fond_s=21,
                              pie_fig_dir=fig_dir)

            elif input_dst_type == "fqdn":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=party_fqdn_traffic,
                              fig_w=32,
                              fig_h=16,
                              fond_s=21,
                              pie_fig_dir=fig_dir)

            elif input_dst_type == "org":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=party_org_traffic,
                              fig_w=32,
                              fig_h=16,
                              fond_s=21,
                              pie_fig_dir=fig_dir)

        elif input_plot_type == "barhplot":
            if input_dst_type == "sld":
                make_bar_h_plot(party_t_dict=party_sld_traffic,
                                dst_type_name=input_dst_type,
                                fig_h=24,
                                fig_w=18,
                                barh_fig_dir=fig_dir)

            elif input_dst_type == "fqdn":
                make_bar_h_plot(party_t_dict=party_fqdn_traffic,
                                dst_type_name=input_dst_type,
                                fig_h=24,
                                fig_w=18,
                                barh_fig_dir=fig_dir)

            elif input_dst_type == "org":
                make_bar_h_plot(party_t_dict=party_org_traffic,
                                dst_type_name=input_dst_type,
                                fig_h=24,
                                fig_w=18,
                                barh_fig_dir=fig_dir)

    if linear:
        for plot_type, dst_type in zip(plot_types, dst_types):
            make_plot(plot_type, dst_type)

    else:
        for plot_type in plot_types:
            for dst_type in dst_types:
                make_plot(plot_type, dst_type)


def write_hosts_by_party(party_dict, fname):
    with open(fname, "w+") as f:
        for p in party_dict:
            f.write(p + " party dst:\n")
            for sld in party_dict[p]:
                f.write(sld + "\n")


def check_dir_exist(ori_path, new_dir):
    new_path = os.path.join(ori_path, new_dir)
    if not os.path.exists(new_path):
        os.mkdir(new_path)
    return new_path
