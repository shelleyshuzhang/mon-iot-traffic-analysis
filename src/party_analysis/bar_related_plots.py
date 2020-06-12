import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as ticker
from protocol_analysis import visualization_protocols as vis
import gc


def bar_h_plot(data: list, names: list, title, color_p,
               fig_dpi, num_name, save_name):
    if names.__len__() >= 20:
        col_start = 30
    else:
        col_start = 20

    data_total = np.array(data).sum()
    labels = []
    for d in data:
        num_label = vis.network_traffic_units(d)
        label = num_label + "-" + str(round(d / data_total * 100, 2)) + "%"
        labels.append(label)
    index = 0
    for n in names:
        names[index] = n + "(" + labels[index] + ")"
        index += 1

    data_d = {num_name: pd.Series(data, index=names)}

    fig = plt.figure(figsize=(18, 20))
    plt.rcParams['font.size'] = 16
    ax = fig.add_subplot(111)
    df = pd.DataFrame(data_d)
    df = df.sort_values(by=num_name)

    color_trans = 0.7
    sub_palette = plt.get_cmap(color_p)
    stop_index = col_start + 10 * len(df)
    palette = [sub_palette(color_index) for color_index in range(col_start,
                                                                 stop_index,
                                                                 10)]
    df[num_name].plot(kind='barh', ax=ax, alpha=color_trans,
                      legend=labels, color=palette,
                      edgecolor='w', title=title)

    ax.set_xscale('log')
    ax.xaxis.set_minor_locator(ticker.LogLocator(subs="all"))
    # ax.xaxis.set_minor_formatter(ticker.LogFormatterSciNotation(minor_thresholds=(np.inf, np.inf)))
    # # You would need to erase default major ticklabels
    # ax1.set_yticklabels([''] * len(ax1.get_yticklabels()))
    # y_major = MultipleLocator(0.1)
    # y_minor = MultipleLocator(0.01)
    # ax1.yaxis.set_major_locator(y_major)
    # ax1.yaxis.set_minor_locator(y_minor)

    # Set grid lines (dotted lines inside plot)
    ax.grid(True, which='major')
    ax.grid(True, which='minor')
    # Remove plot frame
    ax.set_frame_on(False)

    # # Customize title, set position, allow space on top of plot for title
    ax.set_title(ax.get_title(), fontsize=20, alpha=color_trans, ha='center')
    plt.savefig(save_name, bbox_inches='tight', dpi=fig_dpi)
    print("    Plot saved to \"%s\"" % save_name)
    plt.close(fig)
    gc.collect()


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
