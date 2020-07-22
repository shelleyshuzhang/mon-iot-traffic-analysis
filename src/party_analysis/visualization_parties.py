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
host_name_too_long = {"0": 'Other first parties',
                      "1": 'Other support parties',
                      "2": 'Other third parties',
                      "-1": 'Other local parties',
                      "2.5": 'Other advertisers',
                      "3": 'Other analytics'}
dst_type_name_dict = {"SLD": "Second level domain",
                      "FQDN": "Fully qualified domain",
                      "ORG": "Organization"}
patch_dict = {"0": '0',
              "1": '1',
              "2": '2',
              "3": '-1',
              "4": '2.5',
              "5": '3'}


def calc_party_pct(previous_data: list, company: str, fig_dir: str, fig_dpi: int,
                   dst_types: list, plot_types: list, linear: bool):
    party_sld_traffic = {"0": {}, "1": {}, "2": {},
                         "-1": {}, "2.5": {}, "3": {}}
    party_fqdn_traffic = {"0": {}, "1": {}, "2": {},
                          "-1": {}, "2.5": {}, "3": {}}
    party_org_traffic = {"0": {}, "1": {}, "2": {},
                         "-1": {}, "2.5": {}, "3": {}}

    fig_dir = check_dir_exist(fig_dir, "dst_party_analysis")

    for dst_pro in previous_data:
        current_domain_sld: str = dst_pro.host.host
        current_domain_fqdn: str = dst_pro.host.host_full
        current_domain_org: str = dst_pro.host.organization
        current_party = dst_pro.host.party
        current_party = party_index_dict[current_party]
        size = int(dst_pro.snd)

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

    def make_pie_plot(dst_type_name, party_t_dict, fig_dpi, pie_fig_dir):
        pie_fig_dir = check_dir_exist(pie_fig_dir, "pie")
        pie_fig_dir = check_dir_exist(pie_fig_dir, dst_type_name)
        dst_type_name = dst_type_name.upper()
        # plot the percentage of different parties - destinations
        prp.pie_plot_percentage(party_dict=party_t_dict,
                                title="The percentages of each party in all destination "
                                      + dst_type_name + "s (" + company.capitalize() + " device)",
                                save_name=pie_fig_dir + "/" + company
                                          + "_device_parties_pie_"
                                          + dst_type_name + ".png",
                                name_dict=party_name_dict, fig_dpi=fig_dpi)

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
                                     party_bar_plot=[party_bar_dict[p], party_bar_dict[p1]],
                                     save_name=pie_fig_dir + "/" + company + "_pie_"
                                               + dst_type_name + "_" + p.split()[0]
                                               + "_" + p1.split()[0] + "_party_traffic.png",
                                     title="The percentage of traffic sent "
                                           "to each destination " + dst_type_name
                                           + " (" + company.capitalize() + " device)",
                                     name_dict=party_name_dict,
                                     third_party_color=[party_color_dict[party_bar_dict[p]],
                                                        party_color_dict[party_bar_dict[p1]]],
                                     host_name_too_long=host_name_too_long,
                                     empty_parties=[non_data1, non_data2],
                                     fig_dpi=fig_dpi, patch_dict=patch_dict)

    def make_bar_h_plot(party_t_dict, dst_type_name, fig_dpi, barh_fig_dir):
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
                    if all_hosts_len > 25 and \
                            ((p != "Advertiser" and current_t / all_t <= 0.001)
                             or (p == "Advertiser" and current_t / all_t <= 0.002)
                             or (p == "Advertiser" and all_hosts_len >= 50 and current_t / all_t <= 0.01)
                             or (p != "Advertiser" and all_hosts_len >= 50 and current_t / all_t <= 0.002)):
                        other_h_t += current_t
                        too_small_h.append(host)
                if other_h_t > 0:
                    all_hosts[host_name_too_long[party_name]] = other_h_t
                    for h in too_small_h:
                        del all_hosts[h]

                brp.bar_h_plot(data=list(all_hosts.values()), names=list(all_hosts.keys()),
                               title="The percentage of traffic sent to each destination "
                                     + dst_type_name + " (" + company.capitalize() + "/" + p + ")",
                               color_p=party_color_dict[party_bar_dict[p]], fig_dpi=fig_dpi,
                               num_name="Amount of traffic shown using log scale (Bytes)",
                               save_name=barh_fig_dir + "/" + company + "_bar_" + dst_type_name
                                         + "_" + p.split()[0] + "_party_traffic.png")

    def make_plot(input_plot_type: str, input_dst_type: str, fig_dpi: int):
        if input_plot_type == "pieplot":
            if input_dst_type == "sld":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=party_sld_traffic,
                              fig_dpi=fig_dpi,
                              pie_fig_dir=fig_dir)

            elif input_dst_type == "fqdn":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=party_fqdn_traffic,
                              fig_dpi=fig_dpi,
                              pie_fig_dir=fig_dir)

            elif input_dst_type == "org":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=party_org_traffic,
                              fig_dpi=fig_dpi,
                              pie_fig_dir=fig_dir)

        elif input_plot_type == "barhplot":
            if input_dst_type == "sld":
                make_bar_h_plot(party_t_dict=party_sld_traffic,
                                dst_type_name=input_dst_type,
                                fig_dpi=fig_dpi,
                                barh_fig_dir=fig_dir)

            elif input_dst_type == "fqdn":
                make_bar_h_plot(party_t_dict=party_fqdn_traffic,
                                dst_type_name=input_dst_type,
                                fig_dpi=fig_dpi,
                                barh_fig_dir=fig_dir)

            elif input_dst_type == "org":
                make_bar_h_plot(party_t_dict=party_org_traffic,
                                dst_type_name=input_dst_type,
                                fig_dpi=fig_dpi,
                                barh_fig_dir=fig_dir)

    if linear:
        for plot_type, dst_type in zip(plot_types, dst_types):
            make_plot(plot_type, dst_type, fig_dpi)

    else:
        for plot_type in plot_types:
            for dst_type in dst_types:
                make_plot(plot_type, dst_type, fig_dpi)


def write_hosts_by_party(party_dict, fname):
    with open(fname, "w+") as f:
        for p in party_dict:
            f.write(p + " party dst:\n")
            for sld in party_dict[p]:
                f.write(sld + "\n")


def check_dir_exist(ori_path, new_dir):
    new_path = os.path.join(ori_path, new_dir)
    if not os.path.exists(new_path):
        os.system("mkdir -pv %s" % new_path)
    return new_path
