# Getting Started

This document provides a step-by-step starting guide to performing destination and encryption analysis with the code in this repository. A part of this software relies on the destination analysis section of the code accompanying the paper "Information Exposure From Consumer IoT Devices: A Multidimensional, Network-Informed Measurement Approach" in proceedings of the ACM Internet Measurement Conference 2019 (IMC 2019). That code (which will be referred to as the "IMC'19 code") can be found here: https://github.com/dng24/intl-iot. **In-depth information about this software can be found in the [README](README.md).**

## Setup

Setup involves setting up the destination analysis part of the IMC'19 code.

1) Read the [System Setup](https://github.com/dng24/intl-iot/blob/master/Getting_Started.md#system-setup) section in the Getting Started document of the IMC'19 code.

2) Follow the instructions in the [Environmental Setup](https://github.com/dng24/intl-iot/blob/master/Getting_Started.md#environment-setup) section in the Getting Started document of the IMC'19 code.

3) Follow the instructions in the [Destination Analysis Setup](https://github.com/dng24/intl-iot/blob/master/Getting_Started.md#setup) section of the Getting Started document of the IMC'19 code.

4) Install the following dependencies:

```
pip install adblockparser
apt-get install whois
```

5) Clone this Git Repository: `git clone https://github.com/shelleyshuzhang/neu_mon-iot-_network_traffic_analysis.git`

6) Go to the `src` directory: `cd neu_mon-iot-_network_traffic_analysis/src/`

At this point, the software has been setup for use.

## Running the Software

### Very Basic Usage

Very basic usage: `python3 main.py -i PCAP_DIR -m MAC_ADDR -s IMC_DIR`

For input, very basic usage requires a directory containing the pcap files for analysis (`-i`), the MAC address of the device from which the input pcap files were generated from (`-m`), and the path to the `intl-iot/` directory of the IMC'19 software (`-s`). An optional `-c` can be used to specify the manufacturer of the device if known.

For output, a CSV file containing the destination and encryption analyses is generated. For in depth information about the contents of the CSV file, see the [Main CSV Output](README.md#main-csv-output) section of the README.

Example 1: `python3 main.py -i ../../amazon-experiment-raw-traffic/8:a6:bc:7f:a0:41/ -m 08:a6:bc:7f:a0:41 -s ../../intl-iot/ -c amazon`

- Output: A CSV file named `results.csv` is produced in the current directory (`src/`). Another CSV file named `amazon_tmp.csv` is also produced in a newly created directory named `plots/`. This CSV file is the output of running the IMC'19 destination analysis with the following command: `python3 analyze.py -i ../../../amazon-experiment-raw-traffic/8:a6:bc:7f:a0:41/ -m 08:a6:bc:7f:a0:41 -o plots/amazon_tmp.csv`.

### Passing in an Existing IMC'19 Destination Analysis CSV File

If you already have the output CSV for a dataset from the IMC'19 destination pipeline, you can pass it into this software using the (`-v`) option instead of providing the (`-s`) option. Providing the `-v` option skips the IMC'19 destination analysis step, which can save a lot of time.

Example 2: `python3 main.py -i ../../amazon-experiment-raw-traffic/8:a6:bc:7f:a0:41/ -m 08:a6:bc:7f:a0:41 -v plots/amazon_tmp.csv`

- Output: An output CSV named `results.csv` is produced in the current directory (`src/`).
 
### Producing Plots

Plots can also be produced using the `-d` and `-p` options. These options are comma-separated lists of plot attributes. The `-d` option determines the type of data to use to generate the plot, while the `-p` option determines the type of plot to generate.

Currently, input into the `-d` option can be either `fqdn` (fully-qualified domain name), `org` (organization), or `sld` (second-level domain). The input into the `-p` option can either be `BarHPlot` (horizontal bar plot) or `PiePlot` (pie plot).

Example 3: `python3 main.py -i ../../amazon-experiment-raw-traffic/8:a6:bc:7f:a0:41/ -m 08:a6:bc:7f:a0:41 -s ../../intl-iot/ -d org,sld -p BarHPlot,PiePlot`

- Output: An output CSV named `results.csv` is produced in the current directory (`src/`). The graphs produced are located in directories in the following hierarchy: `plots/<analysis_type>/<plot_type>/<dst_type>/<plot_name>.png`. In this case, four graphs are produced:
  - a horizontal bar plot using organization information
  - a horizontal bar plot using second-level domain information
  - a pie plot using organization information
  - a pie plot using second-level domain information

For more information and advanced options, see the [README](README.md).

