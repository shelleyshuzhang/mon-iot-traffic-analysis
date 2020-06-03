import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from protocol_analysis import visualization_protocols as vis


def bar_plot_horizontal(data: list, names: list, height, wide, title, color_p, num_name, save_name):
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

    fig = plt.figure(figsize=(height, wide))
    plt.rcParams['font.size'] = 16
    ax = fig.add_subplot(111)
    df = pd.DataFrame(data_d)
    df = df.sort_values(by=num_name)

    color_trans = 0.7
    sub_palette = plt.get_cmap(color_p)
    stop_index = 20 + 10 * len(df)
    palette = [sub_palette(color_index) for color_index in range(0, stop_index, 10)]
    df[num_name].plot(kind='barh', ax=ax, alpha=color_trans,
                      legend=labels, color=palette,
                      edgecolor='w', title=title)

    plt.xscale('log')
    # Remove grid lines (dotted lines inside plot)
    ax.grid(False)
    # Remove plot frame
    ax.set_frame_on(False)

    # # Customize title, set position, allow space on top of plot for title
    ax.set_title(ax.get_title(), fontsize=20, alpha=color_trans, ha='center')

    plt.savefig(save_name, bbox_inches='tight', dpi=300)
    print("    Plot saved to \"%s\"" % save_name)
    plt.close()
