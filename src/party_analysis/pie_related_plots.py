import copy

import matplotlib.pyplot as plt
from matplotlib.patches import ConnectionPatch
import numpy as np
import pandas as pd
from protocol_analysis import visualization_protocols as vis
import gc


def pie_plot_percentage(party_dict: dict, title, save_name, name_dict, fig_dpi):
    plt.figure(figsize=(16, 10))
    plt.rcParams['font.size'] = 12
    palette = plt.get_cmap('Set1')
    labels = []
    values = []
    colors = []
    index = 0
    for party in party_dict:
        current_value = party_dict[party].__len__()
        labels.append(name_dict[party] + " - " + str(current_value))
        values.append(current_value)
        colors.append(palette(index))
        if index == 4:
            index += 3
        index += 1
    total_values = np.array(values).sum()
    index_v = 0
    for v in values:
        percent = round(v / total_values * 100, 2)
        labels[index_v] += " (" + str('%1.2f' % percent) + "%)"
        index_v += 1
    plt.pie(values, colors=colors, labels=values, autopct='%1.2f%%', counterclock=False)
    t = plt.title(title)
    t.set_ha("left")
    plt.gca().axis("equal")
    plt.legend(labels, loc="right", bbox_to_anchor=(0.9, 0.5), bbox_transform=plt.gcf().transFigure)
    plt.subplots_adjust(left=0.2, bottom=0.1, right=0.7)
    plt.savefig(save_name, dpi=fig_dpi, bbox_inches="tight")
    print("    Plot saved to \"" + save_name + "\"")
    plt.close()


def plot_traffic_dst(party_hosts_traffic: dict, title, save_name, party_bar_plot: list,
                     name_dict, third_party_color: list, host_name_too_long, fig_dpi,
                     empty_parties, patch_dict):
    party_hosts_traffic = copy.deepcopy(party_hosts_traffic)
    if empty_parties[0]:
        plt.rcParams['font.size'] = 16
        current = plt.figure(figsize=(20, 12))
        sub1 = current.add_subplot(1, 2, 1)
        sub3 = current.add_subplot(1, 2, 2)
        sub2 = None
        # move the white spaces between the bar and pie plots
        current.subplots_adjust(wspace=-0.3)
    elif empty_parties[1]:
        plt.rcParams['font.size'] = 16
        current = plt.figure(figsize=(20, 12))
        sub1 = current.add_subplot(1, 2, 1)
        sub2 = current.add_subplot(1, 2, 2)
        sub3 = None
        # move the white spaces between the bar and pie plots
        current.subplots_adjust(wspace=-0.3)
    else:
        plt.rcParams['font.size'] = 12.5
        current = plt.figure(figsize=(20, 10))
        sub1 = current.add_subplot(1, 3, 2)
        sub3 = current.add_subplot(1, 3, 3)
        sub2 = current.add_subplot(1, 3, 1)
        # move the white spaces between the bar and pie plots
        current.subplots_adjust(wspace=-0.45)

    # pie chart textprops={'fontsize': 18}
    palette = plt.get_cmap('Set1')
    labels = []
    values = []
    colors = []
    num_labels = []
    col_index = 0
    for party in party_hosts_traffic:
        labels.append(name_dict[party])
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
                     or (party == "2.5" and current_t / all_t <= 0.01)):
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
    patches, texts = sub1.pie(values, colors=colors, counterclock=False, radius=1)
    labels = ['{0} - {1:1.2f}%'.format(i, j) for i, j in zip(labels, por_cent)]
    l_index = 0
    while l_index < labels.__len__():
        labels[l_index] += (" (" + num_labels[l_index] + ")")
        l_index += 1
    # move the position of pie plot labels
    sub1.legend(patches, labels, loc='center left', bbox_to_anchor=(0.25, -0.04))

    if sub2 is not None and sub3 is not None:
        sub1.set_title(title, x=0.5, y=1.05)
        plot_bar_attached(sub1=sub1,
                          sub2=sub3,
                          third_party_color=third_party_color[1],
                          party_bar_plot=party_bar_plot[1],
                          party_hosts_traffic=party_hosts_traffic,
                          values=values,
                          legend_pos=(0.9, 1.),
                          patch_dict=patch_dict,
                          on_left=False)
        plot_bar_attached(sub1=sub1,
                          sub2=sub2,
                          third_party_color=third_party_color[0],
                          party_bar_plot=party_bar_plot[0],
                          party_hosts_traffic=party_hosts_traffic,
                          values=values,
                          legend_pos=(0.04, 1.),
                          patch_dict=patch_dict,
                          on_left=True)
    elif sub3 is not None:
        sub1.set_title(title, x=0.8, y=1.1)
        plot_bar_attached(sub1=sub1,
                          sub2=sub3,
                          third_party_color=third_party_color[1],
                          party_bar_plot=party_bar_plot[1],
                          party_hosts_traffic=party_hosts_traffic,
                          values=values,
                          legend_pos=(0.92, 1.),
                          patch_dict=patch_dict,
                          on_left=False)
    elif sub2 is not None:
        sub1.set_title(title, x=0.8, y=1.1)
        plot_bar_attached(sub1=sub1,
                          sub2=sub2,
                          third_party_color=third_party_color[0],
                          party_bar_plot=party_bar_plot[0],
                          party_hosts_traffic=party_hosts_traffic,
                          values=values,
                          legend_pos=(0.92, 1.),
                          patch_dict=patch_dict,
                          on_left=False)

    current.savefig(save_name, dpi=fig_dpi)
    print("    Plot saved to \"" + save_name + "\"")
    plt.close(current)
    gc.collect()


def plot_bar_attached(sub1, sub2, third_party_color,
                      party_bar_plot, party_hosts_traffic,
                      values, legend_pos, patch_dict, on_left):
    # bar for second party
    x_pos = 0
    bottom = 0
    values_sub1: dict = {}
    width = 0.2
    colors_sub = []
    sub_palette = plt.get_cmap(third_party_color)

    this_party = patch_dict[party_bar_plot]
    all_hosts: dict = party_hosts_traffic[this_party]

    if all_hosts.__len__() >= 20:
        sub_index = 40
    else:
        sub_index = 60

    df = pd.DataFrame.from_dict(all_hosts, orient='index')
    df = df.sort_values(by=0)
    all_hosts = df.to_dict()[0]

    try:
        for sub_name in all_hosts:
            values_sub1[sub_name] = (float(all_hosts[sub_name])
                                     / float(values[int(party_bar_plot)]))
            colors_sub.append(sub_index)
            if all_hosts.__len__() > 10:
                sub_index += 10
            else:
                sub_index += 15
    except ZeroDivisionError:
        return

    colors_sub.reverse()
    color_index = 0
    sub2_por_cent = []
    too_many_percent = values_sub1.__len__() > 15
    for v_name in values_sub1:
        v = values_sub1[v_name]
        height = v
        sub2.bar(x_pos, height, width, bottom=bottom,
                 color=sub_palette(colors_sub[color_index]))
        y_pos = bottom + sub2.patches[color_index].get_height() / 2
        bottom += height

        # write the percentage on the bar plot
        if (too_many_percent and v > 0.015) or (not too_many_percent and v > 0.01):
            sub2.text(x_pos, y_pos, vis.network_traffic_units(all_hosts[v_name]), ha='center')

        sub2_por_cent.append(round(sub2.patches[color_index].get_height(), 4) * 100)
        color_index += 1

    sub2_por_cent = reversed(np.array(sub2_por_cent))
    sub2_labels = reversed(np.char.array(list(all_hosts.keys())))
    sub2_labels = ['{0} - {1:1.2f}%'.format(i, j) for i, j in zip(sub2_labels, sub2_por_cent)]
    # move the position of bar plot labels
    sub2.legend(reversed(sub2.patches), sub2_labels,
            loc='upper center', bbox_to_anchor=legend_pos)
    sub2.axis('off')
    # 2.5
    sub2.set_xlim(-2.5 * width, 2.5 * width)

    # draw connecting lines
    theta1, theta2 = sub1.patches[int(party_bar_plot)].theta1, \
                     sub1.patches[int(party_bar_plot)].theta2
    center, r = sub1.patches[int(party_bar_plot)].center, \
                sub1.patches[int(party_bar_plot)].r
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

    bar_line_pos = width if on_left else - width
    con2 = ConnectionPatch(xyA=(bar_line_pos / 2, height2), xyB=(x2, y2),
                           coordsA="data", coordsB="data",
                           axesA=sub2, axesB=sub1)
    con2.set_color([0, 0, 0])
    con2.set_linewidth(2)
    sub2.add_artist(con2)

    con1 = ConnectionPatch(xyA=(bar_line_pos / 2, height1), xyB=(x1, y1), coordsA="data",
                           coordsB="data", axesA=sub2, axesB=sub1)
    con1.set_color([0, 0, 0])
    con1.set_linewidth(2)
    sub2.add_artist(con1)
