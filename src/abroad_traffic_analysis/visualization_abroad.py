import numpy as np
from party_analysis import visualization_parties as vsp
from party_analysis import pie_related_plots as prp
from party_analysis import bar_related_plots as brp

country_name_dict = {"0": "US/Local", "1": "Abroad", "-1": "Unknown"}
country_color_dict = {"0": 'Reds', "1": 'Blues', "-1": 'Greens'}
country_name_too_long = {"0": 'other US or local destinations',
                         "1": 'other abroad destinations',
                         "-1": 'other unknown destinations'}
patch_dict = {"0": "0",
              "1": "1",
              "2": "-1"}
protocol_details = {"TCP port: 443": "Https",
                    "TCP port: 80": "Http",
                    "UDP port: 80": "Http"}


def run(previous_data: list, company: str, fig_dir: str, fig_dpi: int,
        dst_types: list, plot_types: list, linear: bool):
    country_info_sld, \
    country_info_fqdn, \
    country_info_org, \
    abroad_all_info_sld, \
    abroad_all_info_fqdn, \
    abroad_all_info_org = read_dst_countries(previous_data)

    fig_dir = vsp.check_dir_exist(ori_path=fig_dir,
                                  new_dir="country_analysis")

    def make_pie_plot(dst_type_name, party_t_dict, fig_dpi, pie_fig_dir):
        pie_fig_dir = vsp.check_dir_exist(pie_fig_dir, "pie")
        pie_fig_dir = vsp.check_dir_exist(pie_fig_dir, dst_type_name)
        dst_type_name = dst_type_name.upper()

        non_data1 = party_t_dict["1"].__len__() == 0
        non_data2 = party_t_dict["-1"].__len__() == 0
        if not non_data1 or not non_data2:
            prp.plot_traffic_dst(party_hosts_traffic=party_t_dict,
                                 party_bar_plot=["1", "2"],
                                 save_name=pie_fig_dir + "/" + company + "_pie_"
                                           + dst_type_name + "_abroad_traffic.png",
                                 title='The amount of traffic sent to each '
                                       'destination ' + dst_type_name +
                                       ' in the USA and abroad (' + company +
                                       ' device/in bytes)',
                                 name_dict=country_name_dict,
                                 third_party_color=[country_color_dict["1"],
                                                    country_color_dict["-1"]],
                                 host_name_too_long=country_name_too_long,
                                 empty_parties=[non_data1, non_data2],
                                 fig_dpi=fig_dpi, patch_dict=patch_dict)

    def make_bar_h_plot(party_t_dict, dst_type_name, fig_dpi, barh_fig_dir):
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
                party_t_dict["other abroad destinations"] = other_h_t
                for h in too_small_h:
                    del party_t_dict[h]
            brp.bar_h_plot(data=list(party_t_dict.values()), names=list(party_t_dict.keys()),
                           title="The percentage of traffic sent "
                                 "abroad to each destination " + dst_type_name
                                 + " and protocol&port and party (" + company + "/Bytes)",
                           color_p=country_color_dict["1"], fig_dpi=fig_dpi,
                           num_name="Amount of traffic shown using log scale (Bytes)",
                           save_name=barh_fig_dir + "/" + company + "_bar_" + dst_type_name
                                     + "_abroad_traffic.png")

    def make_plot(input_plot_type: str, input_dst_type: str, fig_dpi: int):
        if input_plot_type == "pieplot":
            if input_dst_type == "sld":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=country_info_sld,
                              fig_dpi=fig_dpi, pie_fig_dir=fig_dir)

            elif input_dst_type == "fqdn":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=country_info_fqdn,
                              fig_dpi=fig_dpi, pie_fig_dir=fig_dir)

            elif input_dst_type == "org":
                make_pie_plot(dst_type_name=input_dst_type,
                              party_t_dict=country_info_org,
                              fig_dpi=fig_dpi, pie_fig_dir=fig_dir)

        elif input_plot_type == "barhplot":
            if input_dst_type == "sld":
                make_bar_h_plot(party_t_dict=abroad_all_info_sld,
                                dst_type_name=input_dst_type,
                                fig_dpi=fig_dpi, barh_fig_dir=fig_dir)

            elif input_dst_type == "fqdn":
                make_bar_h_plot(party_t_dict=abroad_all_info_fqdn,
                                dst_type_name=input_dst_type,
                                fig_dpi=fig_dpi, barh_fig_dir=fig_dir)

            elif input_dst_type == "org":
                make_bar_h_plot(party_t_dict=abroad_all_info_org,
                                dst_type_name=input_dst_type,
                                fig_dpi=fig_dpi, barh_fig_dir=fig_dir)

    if linear:
        for plot_type, dst_type in zip(plot_types, dst_types):
            make_plot(plot_type, dst_type, fig_dpi)

    else:
        for plot_type in plot_types:
            for dst_type in dst_types:
                make_plot(plot_type, dst_type, fig_dpi)


def read_dst_countries(result):
    def add_to_pie_groups(group_dict, dst: str):
        c_name = country + '(' + dst + ')'
        if country == "Local" or country == "US":
            if c_name in group_dict["0"]:
                group_dict["0"][c_name] += traffic
            else:
                group_dict["0"][c_name] = traffic
        elif country.startswith("Unknown"):
            if c_name in group_dict["-1"]:
                group_dict["-1"][c_name] += traffic
            else:
                group_dict["-1"][c_name] = traffic
        else:
            if c_name in group_dict["1"]:
                group_dict["1"][c_name] += traffic
            else:
                group_dict["1"][c_name] = traffic

    def add_to_bar_plot(plot_group, c_name):
        c_name = country + "(" + c_name + "-" + protocol_port + ")"
        if c_name in plot_group:
            plot_group[c_name] += traffic
        else:
            plot_group[c_name] = traffic

    country_info_sld = {"0": {}, "1": {}, "-1": {}}
    country_info_fqdn = {"0": {}, "1": {}, "-1": {}}
    country_info_org = {"0": {}, "1": {}, "-1": {}}
    abroad_all_info_sld = {}
    abroad_all_info_fqdn = {}
    abroad_all_info_org = {}
    for dst_pro in result:
        host = dst_pro.host.host
        host_full = dst_pro.host.host_full
        org = dst_pro.host.organization
        protocol_port = dst_pro.protocol_port.protocol_port
        traffic = dst_pro.rcv
        country: str = dst_pro.host.country

        if protocol_port in protocol_details:
            protocol_port = protocol_details[protocol_port]

        add_to_pie_groups(country_info_sld, host)
        add_to_pie_groups(country_info_fqdn, host_full)
        add_to_pie_groups(country_info_org, org)

        if country != "US" and country != "Local" \
                and not country.startswith("Unknown"):
            add_to_bar_plot(abroad_all_info_sld, host)
            add_to_bar_plot(abroad_all_info_fqdn, host_full)
            add_to_bar_plot(abroad_all_info_org, org)

    return country_info_sld, \
           country_info_fqdn, \
           country_info_org, \
           abroad_all_info_sld, \
           abroad_all_info_fqdn, \
           abroad_all_info_org
