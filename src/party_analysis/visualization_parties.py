import matplotlib.pyplot as plt
from matplotlib.patches import ConnectionPatch
import csv
import numpy as np
from protocol_analysis import visualization as vis

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


def calculate_party_percentage(csv_filename: str, company: str, fig_dir: str):
    result = {"0": {}, "1": {}, "2": {}, "-1": {}, "2.5": {}, "3": {}}
    with open(csv_filename, mode="r") as csv_file1:
        csv_reader = csv.DictReader(csv_file1)

        for row in csv_reader:
            current_domain_sld: str = row['host']
            current_party = row['party']
            current_party = party_index_dict[current_party]
            size = int(row['packet_rcv'])

            if current_party != "-2":
                if current_domain_sld in result[current_party]:
                    result[current_party][current_domain_sld] += size
                else:
                    result[current_party][current_domain_sld] = size

    # plot the percentage of different parties
    pie_plot_percentage(party_dict=result,
                        title="The percentage of first, support and "
                              "third parties in all destinations ("
                              + company + " device/in bytes)",
                        save_name=fig_dir + "/" + company + "_device_parties.png")

    # write all the sld by party for the device
    sld_filename = fig_dir + "/" + company + "_all_sld.txt"
    write_hosts_by_party(party_dict=result, fname=sld_filename)
    print("    Second level domains written to \"" + sld_filename + "\"")

    # plot traffic sent by different parties
    for p in party_bar_dict:
        index = party_index_dict[p]
        if result[index].__len__() != 0:
            plot_traffic_dst(party_hosts_traffic=result,
                             party_bar_plot=party_bar_dict[p],
                             save_name=fig_dir + "/" + company + "_"
                                       + p.split()[0] + "_party_traffic.png",
                             title="The percentage of traffic sent "
                                   "to each destination ("
                                   + company + " device/in bytes)")


def write_hosts_by_party(party_dict, fname):
    with open(fname, "w+") as f:
        for p in party_dict:
            f.write(p + " party sld:\n")
            for sld in party_dict[p]:
                f.write(sld + "\n")


def pie_plot_percentage(party_dict: dict, title, save_name):
    plt.figure(figsize=(10, 6))
    palette = plt.get_cmap('Set1')
    labels = []
    values = []
    colors = []
    index = 0
    for party in party_dict:
        labels.append(party_name_dict[party])
        values.append(party_dict[party].__len__())
        if index == 4:
            index += 1
        colors.append(palette(index))
        index += 1
    plt.pie(values, colors=colors, labels=values, autopct='%1.1f%%',
            counterclock=False, shadow=True)
    plt.title(title)
    plt.legend(labels, loc=3)
    plt.savefig(save_name)
    print("    Plot saved to \"" + save_name + "\"")
    #plt.show()


def plot_traffic_dst(party_hosts_traffic: dict, title, save_name, party_bar_plot):
    plt.rcParams['font.size'] = 18
    current = plt.figure(figsize=(20, 14))
    sub1 = current.add_subplot(121)
    sub2 = current.add_subplot(122)
    current.subplots_adjust(wspace=0)

    # pie chart textprops={'fontsize': 18}
    palette = plt.get_cmap('Set1')
    labels = []
    values = []
    colors = []
    num_labels = []
    col_index = 0
    for party in party_hosts_traffic:
        labels.append(party_name_dict[party])
        total_traffic = 0
        all_hosts: dict = party_hosts_traffic[party]
        all_hosts_len = all_hosts.__len__()
        all_t = int(np.array(list(all_hosts.values())).sum())
        other_h_t = 0
        too_small_h = []
        for host in all_hosts:
            current_t = all_hosts[host]
            total_traffic += current_t
            if all_hosts_len > 20 and \
                    ((party != "2.5" and current_t / all_t <= 0.002)
                     or (party == "2.5" and current_t / all_t <= all_hosts_len * 0.0001)):
                other_h_t += current_t
                too_small_h.append(host)
        if other_h_t > 0:
            all_hosts[host_name_too_long[party]] = other_h_t
            for h in too_small_h:
                del all_hosts[h]
        values.append(total_traffic)
        colors.append(palette(col_index))
        num_label = vis.network_traffic_units(total_traffic)
        num_labels.append(num_label)
        if col_index == 4:
            col_index += 3
        col_index += 1
    values = np.array(values)
    labels = np.char.array(labels)
    por_cent = 100. * values / values.sum()
    patches, texts = sub1.pie(values, labels=num_labels, colors=colors,
                              counterclock=False, shadow=True, radius=1)
    labels = ['{0} - {1:1.2f} %'.format(i, j) for i, j in zip(labels, por_cent)]
    sub1.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.))
    sub1.set_title(title, x=1, y=1.2)

    # bar for second party
    x_pos = 0
    bottom = 0
    values_sub1 = []
    width = 0.2
    colors_sub = []
    sub_palette = plt.get_cmap(party_color_dict[party_bar_plot])

    sub_index = 30
    this_party = party_bar_plot
    if party_bar_plot == "3":
        this_party = "-1"
    elif party_bar_plot == "4":
        this_party = "2.5"
    all_hosts: dict = party_hosts_traffic[this_party]
    try:
        for sub_name in all_hosts:
            values_sub1.append(float(all_hosts[sub_name])
                               / float(values[int(party_bar_plot)]))
            colors_sub.append(sub_index)
            if all_hosts.__len__() > 10:
                sub_index += 12
            else:
                sub_index += 15
    except ZeroDivisionError:
        return
    color_index = 0
    sub2_por_cent = []
    too_many_percent = values_sub1.__len__() > 15
    for v in values_sub1:
        height = v
        sub2.bar(x_pos, height, width, bottom=bottom,
                 color=sub_palette(colors_sub[color_index]))
        y_pos = bottom + sub2.patches[color_index].get_height() / 2
        bottom += height

        # write the percentage on the bar plot
        if (too_many_percent and v > 0.015) or (not too_many_percent and v > 0.01):
            sub2.text(x_pos, y_pos,
                      "%g%%" % (round(sub2.patches[color_index].get_height(), 4) * 100),
                      ha='center')

        sub2_por_cent.append(round(sub2.patches[color_index].get_height(), 4) * 100)
        color_index += 1

    sub2_por_cent = np.array(sub2_por_cent)
    sub2_labels = np.char.array(list(party_hosts_traffic[this_party].keys()))
    sub2_labels = ['{0} - {1:1.2f} %'.format(i, j) for i, j in zip(sub2_labels, sub2_por_cent)]
    sub2.legend(sub2.patches, sub2_labels, loc='upper center', bbox_to_anchor=(0.9, 1.))

    # sub2.legend(dict_to_plot[party_bar_plot].keys(), loc='lower left')
    sub2.axis('off')
    sub2.set_xlim(-2.5 * width, 2.5 * width)

    # draw connecting lines
    theta1, theta2 = sub1.patches[int(party_bar_plot) * 2].theta1, \
                     sub1.patches[int(party_bar_plot) * 2].theta2
    center, r = sub1.patches[int(party_bar_plot) * 2].center, \
                sub1.patches[int(party_bar_plot) * 2].r
    bar_height = sum([item.get_height() for item in sub2.patches])

    x1 = r * np.cos(np.pi / 180 * theta1) + center[0]
    y1 = np.sin(np.pi / 180 * theta1) + center[1]
    x2 = r * np.cos(np.pi / 180 * theta2) + center[0]
    y2 = np.sin(np.pi / 180 * theta2) + center[1]

    if y1 >= y2:
        height1 = bar_height
        height2 = 0
    else:
        height1 = 0
        height2 = bar_height

    con2 = ConnectionPatch(xyA=(- width / 2, height2), xyB=(x2, y2),
                           coordsA="data", coordsB="data",
                           axesA=sub2, axesB=sub1)
    con2.set_color([0, 0, 0])
    con2.set_linewidth(4)
    sub2.add_artist(con2)

    con1 = ConnectionPatch(xyA=(- width / 2, height1), xyB=(x1, y1), coordsA="data",
                           coordsB="data", axesA=sub2, axesB=sub1)
    con1.set_color([0, 0, 0])
    sub2.add_artist(con1)
    con1.set_linewidth(4)

    current.savefig(save_name)
    print("    Plot saved to \"" + save_name + "\"")
    # plt.show()
