import matplotlib.pyplot as plt
from matplotlib.patches import ConnectionPatch
import csv
import numpy as np

name_dict = {"US/Local": "US/Local", "Abroad": "Abroad", "Unknown": "Unknown"}
###############
# for amazon
# dst_file = '../experiment_1.csv'
# company = 'Amazon'
# input_files = ["/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_09.41.57_192.168.110.14.pcap",
#                "/Users/zhangshu/Desktop/traffic-atk/7c_61_66_10_46_18/2019-11-13_10.10.11_192.168.110.14.pcap"]


# for google
dst_file = '../experiment_2.csv'
company = 'Google'
input_files = ["/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_13.49.15_192.168.110.16.pcap",
               "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_16.43.49_192.168.110.16.pcap",
               "/Users/zhangshu/Desktop/traffic-atk/7c_d9_5c_78_53_3d/2019-11-12_17.33.55_192.168.110.16.pcap"]
actual_abroad_ips = ['199.187.193.166', '146.0.227.110',
                     '85.114.159.93', '87.98.252.5',
                     '178.33.230.6', '202.241.208.54',
                     '94.23.144.220', '174.138.12.104',
                     '85.194.240.137', '213.155.156.166',
                     '213.155.156.183', '208.91.197.39']


def run():
    # get abroad info using software 2019IMC
    # dict_country = read_dst_csv(file_name=dst_file)

    # get accurate abroad info after pinging addresses from above
    dict_country = read_dst_csv_after_ping(file_name=dst_file)
    plot_pie_bar_percentage(dict_to_plot=dict_country,
                            title='The amount of traffic '
                                  'sent abroad by '
                                  'the ' + company + ' device (bytes)',
                            figure_name='country%analysis_' + company,
                            name_dict=name_dict,
                            party_bar_plot='Abroad',
                            bar_number='1',
                            third_party_color='Blues')


def read_dst_csv(file_name):
    country_info = {"US/Local": {}, "Abroad": {}, "Unknown": {}}
    with open(file_name, mode='r', encoding='utf-8-sig') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            input_file = row['input_file']
            country: str = row['country']
            host = row['host']
            ip = row['ip']
            traffic_rcv = int(row['traffic_rcv'])
            traffic_snd = int(row['traffic_snd'])
            if input_file in input_files:
                if country == 'US' or ("." in country):
                    country = country + '-' + host
                    if country in country_info["US/Local"]:
                        country_info["US/Local"][country] += traffic_rcv
                    else:
                        country_info["US/Local"][country] = traffic_rcv
                elif country == 'XX':
                    country = country + '-' + host
                    if country in country_info["Unknown"]:
                        country_info["Unknown"][country] += traffic_rcv
                    else:
                        country_info["Unknown"][country] = traffic_rcv
                else:
                    country = country + '-' + host
                    if country in country_info["Abroad"]:
                        country_info["Abroad"][country] += traffic_rcv
                    else:
                        country_info["Abroad"][country] = traffic_rcv
    return country_info


def read_dst_csv_after_ping(file_name):
    country_info = {"US/Local": {}, "Abroad": {}, "Unknown": {}}
    with open(file_name, mode='r', encoding='utf-8-sig') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            input_file = row['input_file']
            country: str = row['country']
            host = row['host']
            ip = row['ip']
            traffic_rcv = int(row['traffic_rcv'])
            if input_file in input_files:
                if ip in actual_abroad_ips:
                    country = country + '-' + host
                    if country in country_info["Abroad"]:
                        country_info["Abroad"][country] += traffic_rcv
                    else:
                        country_info["Abroad"][country] = traffic_rcv
                elif country == 'XX':
                    country = country + '-' + host
                    if country in country_info["Unknown"]:
                        country_info["Unknown"][country] += traffic_rcv
                    else:
                        country_info["Unknown"][country] = traffic_rcv
                else:
                    country = country + '-' + host
                    if country in country_info["US/Local"]:
                        country_info["US/Local"][country] += traffic_rcv
                    else:
                        country_info["US/Local"][country] = traffic_rcv
    return country_info


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


# dict_to_plot: the dict for plotting the pie and bar plots
# title: title of the plot
# figure_name: name to save as a png file
# name_dict: the name of labels in according to the keys in the dict
# party_bar_plot: the name for the bar plot in the dict's keys
# bar_number: the index of the bar to plot in the dict
# third_party_color: the color to plot for the bar
def plot_pie_bar_percentage(dict_to_plot: dict, title, figure_name, name_dict,
                            party_bar_plot, bar_number, third_party_color):
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
    values = np.array(values)
    labels = np.char.array(labels)
    por_cent = 100. * values / values.sum()
    patches, texts = sub1.pie(values, labels=values, colors=colors,
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
                           / float(values[int(bar_number)]))
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
        sub2.text(x_pos, y_pos,
                  "%g%%" % (round(sub2.patches[color_index].get_height(), 4) * 100),
                  ha='center')

        sub2_por_cent.append(round(sub2.patches[color_index].get_height(), 4) * 100)

        color_index += 1

    sub2_por_cent = np.array(sub2_por_cent)
    sub2_labels = np.char.array(list(dict_to_plot[party_bar_plot].keys()))
    sub2_labels = ['{0} - {1:1.2f} %'.format(i, j) for i, j in zip(sub2_labels, sub2_por_cent)]
    sub2.legend(sub2.patches, sub2_labels, loc='upper center', bbox_to_anchor=(0.9, 1.))

    # sub2.legend(dict_to_plot[party_bar_plot].keys(), loc='lower left')
    sub2.axis('off')
    sub2.set_xlim(-2.5 * width, 2.5 * width)

    # draw connecting lines
    theta1, theta2 = sub1.patches[int(bar_number) * 2].theta1, \
                     sub1.patches[int(bar_number) * 2].theta2
    center, r = sub1.patches[int(bar_number) * 2].center, \
                sub1.patches[int(bar_number) * 2].r
    bar_height = sum([item.get_height() for item in sub2.patches])

    x = r * np.cos(np.pi / 180 * theta2) + center[0]
    y = np.sin(np.pi / 180 * theta2) + center[1]
    con = ConnectionPatch(xyA=(- width / 2, bar_height), xyB=(x, y),
                          coordsA="data", coordsB="data",
                          axesA=sub2, axesB=sub1)
    con.set_color([0, 0, 0])
    con.set_linewidth(4)
    sub2.add_artist(con)

    x = r * np.cos(np.pi / 180 * theta1) + center[0]
    y = np.sin(np.pi / 180 * theta1) + center[1]
    con = ConnectionPatch(xyA=(- width / 2, 0), xyB=(x, y), coordsA="data",
                          coordsB="data", axesA=sub2, axesB=sub1)
    con.set_color([0, 0, 0])
    sub2.add_artist(con)
    con.set_linewidth(4)

    current.savefig(figure_name + ".png")
    plt.show()


# means1: each value1 of the given label
# means2: each value2 of the given label
# xlabels: the labels
# name1: the name of value1
# name2: the name of value2
# ylabel: the label on y axis
# title: the title for the plot
# figure_name: the name used to save the figure
def plot_grouped_bars(means1, means2, xlabels, name1, name2, ylabel, title, figure_name):
    x = np.arange(len(xlabels))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots(figsize=(20, 10))
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
