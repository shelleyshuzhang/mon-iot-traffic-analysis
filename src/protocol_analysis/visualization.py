import copy
import matplotlib.pyplot as plt
import numpy as np

from matplotlib.patches import ConnectionPatch

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
protocol_details = {"TCP port: 443": "Https", "TCP port: 80": "Http", "UDP port: 80": "Http"}


# the result is a list of DestinationPro
def run(result: list, company, fig_dir):
    calculate_encrypted_dst_percentage(previous_data=result,
                                       company=company, fig_dir=fig_dir)


def calculate_encrypted_dst_percentage(previous_data: list, company, fig_dir):
    encryption_dict, \
    party_dict_encrypted, \
    party_dict_unencrypted, \
    traffic_dst_unencrypted = group_traffic(previous_data)

    # plot the percentage of encrypted and unencrypted traffic
    pie_plot_percentage(dict_to_plot=encryption_dict,
                        title='Total amount of encrypted and unencrypted '
                              'traffic sent by the ' + company
                              + " device (Bytes)",
                        figure_name=fig_dir + "/" + company + "_traffic_encryption.png",
                        name_dict=protocol_encrypted_dict)

    # plot the percentage of unencrypted traffic sent to each dst and party
    for p in party_dict_unencrypted:
        if party_dict_unencrypted[p].__len__() != 0:
            plot_pie_bar_percentage(dict_to_plot=party_dict_unencrypted,
                                    title="Total amount of unencrypted traffic sent to each "
                                          "party and destination by the " + company
                                          + " device (Bytes)",
                                    figure_name=fig_dir + "/" + company + '_unencrypted_'
                                                + party_name_dict[p].replace(" ", "_") + ".png",
                                    name_dict=party_name_dict,
                                    party_bar_plot=p,
                                    position=party_bar_dict[p],
                                    third_party_color=party_color_dict[p])

    # show the amount of unencrypted traffic sent and received
    # to each destination
    means1 = []
    means2 = []
    for dst in traffic_dst_unencrypted:
        t_snd = traffic_dst_unencrypted[dst][0]
        t_rcv = traffic_dst_unencrypted[dst][1]
        means1.append(t_snd)
        means2.append(t_rcv)
    if means1.__len__() != 0 or means2.__len__() != 0:
        plot_grouped_bars(means1=means1,
                          means2=means2,
                          xlabels=traffic_dst_unencrypted.keys(),
                          name1='traffic_snd',
                          name2='traffic_rcv',
                          ylabel='Traffic in bytes',
                          title='Amount of unencrypted traffic sent '
                                'and received by each destination (' + company + ')',
                          figure_name=fig_dir + "/" + company + "_unencrypted_traffic_dst.png")


def group_traffic(result: list):
    dst_pros = result
    party_dict_encrypted = {"0": {}, "1": {}, "2": {}, "-1": {}, "2.5": {}, "3": {}}
    party_dict_unencrypted = {"0": {}, "1": {}, "2": {}, "-1": {}, "2.5": {}, "3": {}}
    traffic_encrypted_unencrypted = {}
    traffic_dst_unencrypted = {}

    for dst_pro in dst_pros:
        party = party_index_dict[dst_pro.host.party]
        host = dst_pro.host.host
        traffic = dst_pro.rcv
        traffic_snd = dst_pro.snd
        encrypt = dst_pro.protocol_port.encrypted
        if encrypt in traffic_encrypted_unencrypted:
            traffic_encrypted_unencrypted[encrypt] += traffic
        else:
            traffic_encrypted_unencrypted[encrypt] = traffic

        if dst_pro.protocol_port.imp == "1":
            if encrypt == "1":
                if host in party_dict_encrypted[party]:
                    party_dict_encrypted[party][host] += traffic
                else:
                    party_dict_encrypted[party][host] = traffic
            elif encrypt == "0":
                if host in party_dict_unencrypted[party]:
                    party_dict_unencrypted[party][host] += traffic
                else:
                    party_dict_unencrypted[party][host] = traffic

                if host in traffic_dst_unencrypted:
                    traffic_dst_unencrypted[host][0] += traffic_snd
                    traffic_dst_unencrypted[host][1] += traffic
                else:
                    traffic_dst_unencrypted[host] = [traffic_snd, traffic]

    return traffic_encrypted_unencrypted, \
           party_dict_encrypted, \
           party_dict_unencrypted, \
           traffic_dst_unencrypted


# use the proper units for large traffic
def network_traffic_units(traffic_num: int):
    if traffic_num < 1024:
        return str(traffic_num) + " Bytes"
    elif 1024 <= traffic_num < 1048576:
        return str(round(traffic_num / 1024, 2)) + " KB"
    elif 1048576 <= traffic_num < 1073741824:
        return str(round(traffic_num / 1048576, 2)) + " MB"
    elif 1073741824 <= traffic_num < 1099511627776:
        return str(round(traffic_num / 1073741824, 2)) + " GB"
    else:
        return str(round(traffic_num / 1099511627776, 2)) + " TB"


# plot the value in percentage for the given value dict
def pie_plot_percentage(dict_to_plot: dict, title, figure_name, name_dict):
    plt.figure(figsize=(10, 6))
    palette = plt.get_cmap('Set1')
    labels = []
    values = []
    colors = []
    num_labels = []
    index = 0
    for name in dict_to_plot:
        labels.append(name_dict[name])
        values.append(dict_to_plot[name])
        colors.append(palette(index))
        num_label = network_traffic_units(dict_to_plot[name])
        num_labels.append(num_label)
        index += 1
    plt.pie(values, colors=colors, labels=num_labels,
            autopct='%1.1f%%', counterclock=False,
            shadow=True)
    plt.title(title)
    plt.legend(labels, loc=3)
    plt.savefig(figure_name)
    print("    Plot saved to \"" + figure_name + "\"")
    # plt.show()


def plot_pie_bar_percentage(dict_to_plot: dict, title, figure_name,
                            name_dict, party_bar_plot, position,
                            third_party_color):
    plt.rcParams['font.size'] = 18
    current = plt.figure(figsize=(24, 18))
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
    for name in dict_to_plot:
        labels.append(name_dict[name])
        total_traffic = 0
        for value_name in dict_to_plot[name]:
            total_traffic += dict_to_plot[name][value_name]
        values.append(total_traffic)
        colors.append(palette(col_index))
        num_label = network_traffic_units(total_traffic)
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
    sub1.set_title(title, x=1, y=1.3)

    # bar for second party
    x_pos = 0
    bottom = 0
    values_sub1 = []
    width = 0.2
    colors_sub = []
    sub_palette = plt.get_cmap(third_party_color)

    sub_index = 30
    for sub_name in dict_to_plot[party_bar_plot]:
        values_sub1.append(float(dict_to_plot[party_bar_plot][sub_name])
                           / float(values[int(position)]))
        colors_sub.append(sub_index)
        sub_index += 15
    color_index = 0
    sub2_por_cent = []
    for v in values_sub1:
        height = v
        sub2.bar(x_pos, height, width, bottom=bottom,
                 color=sub_palette(colors_sub[color_index]))
        y_pos = bottom + sub2.patches[color_index].get_height() / 2
        bottom += height
        # sub2.text(x_pos, y_pos,
        #           "%g%%" % (round(sub2.patches[color_index].get_height(), 4) * 100),
        #           ha='center')

        sub2_por_cent.append(round(sub2.patches[color_index].get_height(), 4) * 100)

        color_index += 1

    sub2_por_cent = np.array(sub2_por_cent)
    sub2_labels = np.char.array(list(dict_to_plot[party_bar_plot].keys()))
    sub2_labels = ['{0} - {1:1.2f} %'.format(i, j) for i, j in zip(sub2_labels, sub2_por_cent)]
    sub2.legend(sub2.patches, sub2_labels, loc='upper left', bbox_to_anchor=(-0.1, 1.))

    # sub2.legend(dict_to_plot[party_bar_plot].keys(), loc='lower left')
    sub2.axis('off')
    sub2.set_xlim(-2.5 * width, 2.5 * width)

    # draw connecting lines
    theta1, theta2 = sub1.patches[int(position) * 2].theta1, \
                     sub1.patches[int(position) * 2].theta2
    center, r = sub1.patches[int(position) * 2].center, \
                sub1.patches[int(position) * 2].r
    bar_height = sum([item.get_height() for item in sub2.patches])

    x = r * np.cos(np.pi / 180 * theta2) + center[0]
    y = np.sin(np.pi / 180 * theta2) + center[1]
    con = ConnectionPatch(xyA=(- width / 2, 0), xyB=(x, y),
                          coordsA="data", coordsB="data",
                          axesA=sub2, axesB=sub1)
    con.set_color([0, 0, 0])
    con.set_linewidth(4)
    sub2.add_artist(con)

    x = r * np.cos(np.pi / 180 * theta1) + center[0]
    y = np.sin(np.pi / 180 * theta1) + center[1]
    con = ConnectionPatch(xyA=(- width / 2, bar_height), xyB=(x, y), coordsA="data",
                          coordsB="data", axesA=sub2, axesB=sub1)
    con.set_color([0, 0, 0])
    sub2.add_artist(con)
    con.set_linewidth(4)

    current.savefig(figure_name)
    print("    Plot saved to \"" + figure_name + "\"")
    #plt.show()


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
    #plt.show()
