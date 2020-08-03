import matplotlib.pyplot as plt
import numpy as np

from party_analysis import bar_related_plots as brp
from party_analysis import pie_related_plots as prp
from party_analysis import visualization_parties as vsp

party_name_dict = {"-1": "Local", "0": "First party",
                   "1": "Support party", "2": "Third party",
                   "2.5": "Advertisers", "3": "Analytics"}
party_color_dict = {"0": 'Reds', "1": 'Blues', "2": "Greens",
                    "-1": "Purples", "2.5": "Oranges", "3": "Greys"}
party_bar_dict = {"0": "0",
                  "1": "1",
                  "2": "2",
                  "-1": "3",
                  "2.5": "4",
                  "3": "5"}
party_index_dict = {"Physical": "-2", "Local": "-1",
                    "First party": "0", "Support party": "1",
                    "Third party": "2", "Advertisers": "2.5",
                    "Analytics": "3"}

protocol_known_dict = {"1": "well-known", "-1": "unknown", "0.5": "registered"}
protocol_readable_dict = {"1": "human-readable", "0": "human-unreadable",
                          "0.5": "partially human-readable", "-1": "unknown"}
protocol_encrypted_dict = {"1": "encrypted", "0": "unencrypted", "-1": "unknown"}
protocol_importance_dict = {"1": "important", "0": "unimportant", "-1": "unknown"}
protocol_details = {"TCP port: 443": "HTTPS", "TCP port: 80": "HTTP", "UDP port: 80": "HTTP"}
protocol_bar_dict = {"0": "1",
                     "1": "0",
                     "-1": "2"}
protocol_color_dict = {"1": 'Reds', "0": 'Blues', "-1": "Greens"}
protocol_name_too_long = {"0": 'Other unencrypted destinations',
                          "1": 'Other encrypted destinations',
                          "-1": 'Other unknown destinations'}
patch_dict = {"1": "0",
              "0": "1",
              "2": "-1"}


def calc_encrypted_dst_pct(previous_data: list, company: str, fig_dir: str, fig_dpi: int,
                           dst_types: list, plot_types: list, linear: bool):
    traffic_encryption_dst, \
    traffic_encryption_org, \
    traffic_encryption_fqdn, \
    party_dict_unencrypted_sld, \
    party_dict_unencrypted_fqdn, \
    party_dict_unencrypted_org = group_traffic(previous_data)

    fig_dir = vsp.check_dir_exist(fig_dir, "encryption_analysis")

    def make_pie_plot(dst_type_name, party_t_dict, pie_fig_dpi, pie_fig_dir):
        pie_fig_dir = vsp.check_dir_exist(pie_fig_dir, "pie")
        pie_fig_dir = vsp.check_dir_exist(pie_fig_dir, dst_type_name)
        dst_type_name = dst_type_name.upper()

        # plot traffic sent to different parties - destinations
        non_data1 = party_t_dict["0"].__len__() == 0
        non_data2 = party_t_dict["-1"].__len__() == 0
        if not non_data1 or not non_data2:
            prp.plot_traffic_dst(party_hosts_traffic=party_t_dict,
                                 party_bar_plot=[protocol_bar_dict["0"], protocol_bar_dict["-1"]],
                                 save_name=pie_fig_dir + "/" + company + "_pie_"
                                           + dst_type_name + "_encryption_traffic.png",
                                 title="The amount of encrypted and unencrypted traffic "
                                       "sent to each destination " + dst_type_name
                                       + " and protocol&port"
                                       + " (" + company.capitalize() + " device)",
                                 name_dict=protocol_encrypted_dict,
                                 third_party_color=[protocol_color_dict["0"],
                                                    protocol_color_dict["-1"]],
                                 host_name_too_long=protocol_name_too_long,
                                 empty_parties=[non_data1, non_data2],
                                 fig_dpi=pie_fig_dpi, patch_dict=patch_dict)

    def make_bar_h_plot(party_t_dict, dst_type_name, barh_fig_dpi, barh_fig_dir):
        barh_fig_dir = vsp.check_dir_exist(barh_fig_dir, "barH")
        barh_fig_dir = vsp.check_dir_exist(barh_fig_dir, dst_type_name)
        dst_type_name = dst_type_name.upper()

        if party_t_dict.__len__() != 0:
            other_h_t = 0
            too_small_h = []
            for host in party_t_dict:
                current_t = party_t_dict[host]
                all_hosts_len = party_t_dict.__len__()
                all_t = int(np.array(list(party_t_dict.values())).sum())
                if all_hosts_len > 25 and current_t / all_t <= 0.0001:
                    other_h_t += current_t
                    too_small_h.append(host)
            if other_h_t > 0:
                party_t_dict["other unencrypted destinations"] = other_h_t
                for h in too_small_h:
                    del party_t_dict[h]
            brp.bar_h_plot(data=list(party_t_dict.values()), names=list(party_t_dict.keys()),
                           title="The percentages of unencrypted traffic sent "
                                 "to each destination " + dst_type_name
                                 + " and protocol&port and party (" + company.capitalize() + ")",
                           color_p=party_color_dict[party_bar_dict["0"]], fig_dpi=barh_fig_dpi,
                           num_name="Amount of traffic shown using log scale (Bytes)",
                           save_name=barh_fig_dir + "/" + company + "_bar_" + dst_type_name
                                     + "_unencrypted_traffic.png")

    def make_plot(input_plot_type: str, input_dst_type: str, fig_dpi: int):
        if input_plot_type == "pieplot":
            if input_dst_type == "sld":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=traffic_encryption_dst,
                              pie_fig_dpi=fig_dpi, pie_fig_dir=fig_dir)

            elif input_dst_type == "fqdn":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=traffic_encryption_fqdn,
                              pie_fig_dpi=fig_dpi, pie_fig_dir=fig_dir)

            elif input_dst_type == "org":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=traffic_encryption_org,
                              pie_fig_dpi=fig_dpi, pie_fig_dir=fig_dir)

        elif input_plot_type == "barhplot":
            if input_dst_type == "sld":
                make_bar_h_plot(party_t_dict=party_dict_unencrypted_sld,
                                dst_type_name=input_dst_type,
                                barh_fig_dpi=fig_dpi, barh_fig_dir=fig_dir)

            elif input_dst_type == "fqdn":
                make_bar_h_plot(party_t_dict=party_dict_unencrypted_fqdn,
                                dst_type_name=input_dst_type,
                                barh_fig_dpi=fig_dpi, barh_fig_dir=fig_dir)

            elif input_dst_type == "org":
                make_bar_h_plot(party_t_dict=party_dict_unencrypted_org,
                                dst_type_name=input_dst_type,
                                barh_fig_dpi=fig_dpi, barh_fig_dir=fig_dir)

    if linear:
        for plot_type, dst_type in zip(plot_types, dst_types):
            make_plot(plot_type, dst_type, fig_dpi)

    else:
        for plot_type in plot_types:
            for dst_type in dst_types:
                make_plot(plot_type, dst_type, fig_dpi)


def group_traffic(dst_pros: list):
    party_dict_unencrypted_dst = {}
    party_dict_unencrypted_org = {}
    party_dict_unencrypted_fqdn = {}
    traffic_encryption_dst = {"1": {}, "0": {}, "-1": {}}
    traffic_encryption_org = {"1": {}, "0": {}, "-1": {}}
    traffic_encryption_fqdn = {"1": {}, "0": {}, "-1": {}}

    for dst_pro in dst_pros:
        party = dst_pro.host.party
        host = dst_pro.host.host
        host_full = dst_pro.host.host_full
        org = dst_pro.host.organization
        protocol_port = dst_pro.protocol_port.protocol_port
        traffic = dst_pro.snd
        encrypt = dst_pro.protocol_port.encrypted

        if dst_pro.protocol_port.imp == "1":
            if protocol_port in protocol_details:
                protocol_port = protocol_details[protocol_port]

            h_p = host + " (" + protocol_port + ")"
            if h_p in traffic_encryption_dst[encrypt]:
                traffic_encryption_dst[encrypt][h_p] += traffic
            else:
                traffic_encryption_dst[encrypt][h_p] = traffic

            hf_p = host_full + " (" + protocol_port + ")"
            if hf_p in traffic_encryption_fqdn[encrypt]:
                traffic_encryption_fqdn[encrypt][hf_p] += traffic
            else:
                traffic_encryption_fqdn[encrypt][hf_p] = traffic

            ho_p = org + " (" + protocol_port + ")"
            if ho_p in traffic_encryption_org[encrypt]:
                traffic_encryption_org[encrypt][ho_p] += traffic
            else:
                traffic_encryption_org[encrypt][ho_p] = traffic

            if encrypt == "0":
                p_h_pro = host + " (" + protocol_port + "/" + party + ")"
                if p_h_pro in party_dict_unencrypted_dst:
                    party_dict_unencrypted_dst[p_h_pro] += traffic
                else:
                    party_dict_unencrypted_dst[p_h_pro] = traffic

                p_h_pro_f = host_full + " (" + protocol_port + "/" + party + ")"
                if p_h_pro_f in party_dict_unencrypted_fqdn:
                    party_dict_unencrypted_fqdn[p_h_pro_f] += traffic
                else:
                    party_dict_unencrypted_fqdn[p_h_pro_f] = traffic

                p_h_pro_o = org + " (" + protocol_port + "/" + party + ")"
                if p_h_pro_o in party_dict_unencrypted_org:
                    party_dict_unencrypted_org[p_h_pro_o] += traffic
                else:
                    party_dict_unencrypted_org[p_h_pro_o] = traffic

    return traffic_encryption_dst, \
           traffic_encryption_org, \
           traffic_encryption_fqdn, \
           party_dict_unencrypted_dst, \
           party_dict_unencrypted_fqdn, \
           party_dict_unencrypted_org


# use the proper units for large traffic
def network_traffic_units(traffic_num: int):
    if traffic_num < 1024:
        return str(round(traffic_num, 2)) + " bytes"
    elif 1024 <= traffic_num < 1048576:
        return str(round(traffic_num / 1024, 2)) + " KB"
    elif 1048576 <= traffic_num < 1073741824:
        return str(round(traffic_num / 1048576, 2)) + " MB"
    elif 1073741824 <= traffic_num < 1099511627776:
        return str(round(traffic_num / 1073741824, 2)) + " GB"
    else:
        return str(round(traffic_num / 1099511627776, 2)) + " TB"


def plot_grouped_bars(means1, means2, xlabels, name1, name2, ylabel, title, figure_name):
    x = np.arange(len(xlabels))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots(figsize=(22, 10))
    rects1 = ax.bar(x - width / 2, means1, width, label=name1)
    rects2 = ax.bar(x + width / 2, means2, width, label=name2)

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(xlabels)
    ax.legend()

    def autolabel(rects):
        """Attach a text label above each bar in *rects*, displaying its height."""
        for rect in rects:
            height = rect.get_height()
            height_label = network_traffic_units(height)
            ax.annotate('{}'.format(height_label),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')

    autolabel(rects1)
    autolabel(rects2)

    fig.tight_layout()

    plt.savefig(figure_name)
    print("    Plot saved to \"" + figure_name + "\"")
    # plt.show()
