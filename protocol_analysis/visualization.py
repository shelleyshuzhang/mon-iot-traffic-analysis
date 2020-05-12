import copy

import matplotlib.pyplot as plt
from matplotlib.patches import ConnectionPatch
import csv
import numpy as np

from scapy.layers.inet import IP
from scapy.utils import rdpcap

from Source.protocol_analysis.Destination import Destination
from Source.protocol_analysis.DestinationPro import DestinationPro
from Source.protocol_analysis.ProtocolPort import ProtocolPort

options = ('ip', 'host', 'party', 'protocol&port',
           'encrypted', 'well-known', 'human-readable',
           'snd', 'rcv', 'importance')
party_name_dict = {"0": "First party", "1": "Support party",
                   "2": "Third party", "-1": "Non-internet"}
protocol_known_dict = {"1": "well-known", "0": "unknown", "0.5": "registered"}
protocol_readable_dict = {"1": "human-readable", "0": "human-unreadable",
                          "0.5": "partially human-readable"}
protocol_encrypted_dict = {"1": "encrypted", "0": "unencrypted", "-1": "unknown"}
protocol_importance_dict = {"1": "important", "0": "unimportant"}

######################################
company = 'Google'

# for google
device_ip = "192.168.110.16"
# for amazon
# device_ip = "192.168.110.14"

third_party_color_1 = 'Greens'
third_party_color_2 = 'Greens'
csv_file = "./protocol_analysis/dst_pros_google.csv"


def run():
    calculate_encrypted_dst_percentage(csv_file)


def calculate_encrypted_dst_percentage(csv_filename: str):
    encryption_dict, \
    party_dict_encrypted, \
    party_dict_unencrypted, \
    traffic_dst_unencrypted = group_traffic(csv_filename=csv_filename)

    # plot the percentage of encrypted and unencrypted traffic
    pie_plot_percentage(dict_to_plot=encryption_dict,
                        title='Total amount of encrypted and unencrypted '
                              'traffic sent by the ' + company
                              + " device (Bytes)",
                        figure_name="traffic_encryption%_" + company,
                        name_dict=protocol_encrypted_dict)

    # plot the percentage of unencrypted/encrypted traffic sent to each dst and party
    plot_pie_bar_percentage(dict_to_plot=party_dict_encrypted,
                            title="Total amount of encrypted traffic sent to each "
                                  "party and destination by the " + company
                                  + " device (Bytes)",
                            figure_name='encrypted_party%_' + company,
                            name_dict=party_name_dict,
                            party_bar_plot="2",
                            position="2",
                            third_party_color=third_party_color_1)
    plot_pie_bar_percentage(dict_to_plot=party_dict_unencrypted,
                            title="Total amount of unencrypted traffic sent to each "
                                  "party and destination by the " + company
                                  + " device (Bytes)",
                            figure_name='unencrypted_party%_' + company,
                            name_dict=party_name_dict,
                            party_bar_plot="2",
                            position="2",
                            third_party_color=third_party_color_2)

    #
    means1 = []
    means2 = []
    for dst in traffic_dst_unencrypted:
        t_snd = traffic_dst_unencrypted[dst][0]
        t_rcv = traffic_dst_unencrypted[dst][1]
        means1.append(t_snd)
        means2.append(t_rcv)
    plot_grouped_bars(means1=means1,
                      means2=means2,
                      xlabels=traffic_dst_unencrypted.keys(),
                      name1='traffic_snd',
                      name2='traffic_rcv',
                      ylabel='Traffic in bytes',
                      title='Amount of unencrypted traffic sent '
                            'and received by each destination (' + company + ')',
                      figure_name="Unencrypted_traffic_dst_" + company)


def group_traffic(csv_filename):
    dst_pros = list(get_dst_pros(csv_filename=csv_filename))
    party_dict_encrypted = {"0": {}, "1": {}, "2": {}, "-1": {}}
    party_dict_unencrypted = {"0": {}, "1": {}, "2": {}, "-1": {}}
    traffic_encrypted_unencrypted = {}
    traffic_dst_unencrypted = {}

    for dst_pro in dst_pros:
        party = dst_pro.host.party
        host = dst_pro.host.host
        traffic = dst_pro.rcv
        traffic_snd = dst_pro.snd
        if party == "2.5":
            host = "advertisers"
            party = "2"
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


def get_dst_pros(csv_filename):
    with open(csv_filename, mode="r") as csv_file1:
        csv_reader = csv.DictReader(csv_file1)

        for row in csv_reader:
            host_name = row['host']
            current_ip = row['ip']
            party = row['party']
            protocol_port = row['protocol&port']
            traffic_snd = row['snd']
            traffic_rcv = row['rcv']
            well_known = row['well-known']
            readable = row['human-readable']
            encrypted = row['encrypted']
            importance = row['importance']
            dst = Destination(host=host_name, ip=current_ip, party=party)
            protocol = ProtocolPort(protocol_port=protocol_port,
                                    encrypted=encrypted,
                                    expected=well_known,
                                    readable=readable,
                                    importance=importance)
            dst_pro = DestinationPro(dst=dst, pro_port=protocol)
            dst_pro.add_snd(traffic_snd)
            dst_pro.add_rcv(traffic_rcv)
            yield dst_pro


# plot the value in percentage for the given value dict
def pie_plot_percentage(dict_to_plot: dict, title, figure_name, name_dict):
    plt.figure(figsize=(10, 6))
    palette = plt.get_cmap('Set1')
    labels = []
    values = []
    colors = []
    index = 0
    for name in dict_to_plot:
        labels.append(name_dict[name])
        values.append(dict_to_plot[name])
        colors.append(palette(index))
        index += 1
    plt.pie(values, colors=colors, labels=values, autopct='%1.1f%%',
            counterclock=False, shadow=True)
    plt.title(title)
    plt.legend(labels, loc=3)
    plt.savefig(figure_name + ".png")
    plt.show()


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
    col_index = 0
    for name in dict_to_plot:
        labels.append(name_dict[name])
        total_traffic = 0
        for value_name in dict_to_plot[name]:
            total_traffic += dict_to_plot[name][value_name]
        values.append(total_traffic)
        colors.append(palette(col_index))
        col_index += 1
    values_copy = copy.deepcopy(values)
    values = np.array(values)
    labels = np.char.array(labels)
    por_cent = 100. * values / values.sum()
    patches, texts = sub1.pie(values, labels=values_copy, colors=colors,
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

    current.savefig(figure_name + ".png")
    plt.show()


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
            ax.annotate('{}'.format(height),
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')

    autolabel(rects1)
    autolabel(rects2)

    fig.tight_layout()

    plt.savefig(figure_name + ".png")
    plt.show()
