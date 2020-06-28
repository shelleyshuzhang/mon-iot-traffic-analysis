import sys
import os

PATH = sys.argv[0]
SCRIPT_DIR = os.path.dirname(PATH)
if SCRIPT_DIR == "":
    SCRIPT_DIR = "."

RED = "\033[31;1m"
END = "\033[0m"
BEG = RED + PATH

USAGE_STM = """
Usage: sudo python3 {prog_name} -i PCAP_DIR -m MAC_ADDR {{-v IN_CSV | -s IMC_DIR}} [OPTION]...

Performs destination, encryption, and abroad analysis on IoT network traffic. Determines
the percentage of first, support, third, local, advertiser, and analytic party traffic.
Produces a CSV file which includes traffic party, organization, and information
about encryption. Several plots are also generated for visualization.

Example: sudo python3 {prog_name} -i echodot_pcaps/ -m 18:74:2e:41:4d:35 -v echodot_tmp.csv -f figs/ -c amazon -d org,sld -p BarHPlot

Example: sudo python3 {prog_name} -i echodot_pcaps/ -m 18:74:2e:41:4d:35 -s ../intl-iot/ -c amazon -n 4 -o echodot_results.csv

Required arguments:
  -i PCAP_DIR path to the directory containing input pcap files for analysis
  -m MAC_ADDR MAC address of the device that generated the data in PCAP_DIR

  AND EITHER

  -s IMC_DIR  path to the directory containing the code accompanying the paper
                titled "Information Exposure From Consumer IoT Devices: A
                Multidimensional, Network-Informed Measurement Approach" in
                proceedings of the ACM Internet Measurement Conference 2019 (IMC'19);
                the code can be found here: https://github.com/NEU-SNS/intl-iot/

  OR

  -v IN_CSV   path to the output CSV of running destination analysis of the
                IMC'19 code on the pcap files in PCAP_DIR

Optional arguments:
  -c DEV_MFR  company that created the device that generated the data in PCAP_DIR;
                used to identify first parties (Default = unknown)
  -t TIME_RNG time range, in number of days, to split pcaps into for longitudinal
                analysis; can be fractions of a day (Default = 1)
  -f FIG_DIR  path to a directory to place the generated plots; will be generated
                if it does not currently exist (Default = plots/)
  -o OUT_CSV  path to the output CSV file; if it exists, results will be appended,
                else, it will be created (Default = results.csv)
  -d DST_TYPS comma-separated list of data types to use to generate party
                analysis plots; choose from fqdn, org, and sld
  -p PLT_TYPS comma-separated list of plot types to use to generate party analysis
                plots; choose from BarHPlot and PiePlot
  -l          generates plots using DST_TYPS and PLT_TYPS linearly instead of using
                a 2D-array-like style (see below for more information)
  -e DPI      dots per inch (DPI) of a plot (Default = 72)
  -n NUM_PROC number of CPU processes to use to run the destination analysis and
                protocol analysis portions (Default = 1)
  -h          print this usage statement and exit

Notes:
 - sudo is required to ping IP addresses in abroad analysis.
 - Either the -v option or the -s option must be specified. Use the -v option if you
     already have the output CSV generated by the IMC'19 code.
 - Types must be specified in both the -d and -p options to generate plots. DST_TYPS
     is the type of data used to make the plot, while PLT_TYPS is the type of graph
     used to display the data.
 - Example for the -l option: If DST_TYPS is fqdn,org and PLT_TYPS is BarHPlot,PiePlot,
     the following sets of plots would be generated
       - without the -l option: BarHPlot using fqdn, BarHPlot using org, PiePlot using
           fqdn, PiePlot using org.
       - with the -l option: BarHPlot using fqdn, PiePlot using org.
 - If the -l option is specified and DST_TYPS and PLT_TYPS are of different lengths,
     plots will be generated up until there are no more items in a list.

For more information, see the README.""".format(prog_name=PATH)

MISSING = BEG + ": Error: The \"%s\" %s is missing." + END
NO_PERM = BEG + ": Error: \"%s\" does not have %s permission." + END

INVAL = BEG + ": Error: %s \"%s\" is not a %s." + END
WRONG_EXT = BEG + ": Error: %s must be a %s file.\n    Received \"%s\"" + END

NO_IN_DIR = BEG + ": Error: Pcap input directory (-i) required." + END
NO_MAC = BEG + ": Error: MAC address (-m) required." + END
INVAL_MAC = BEG + ": Error: Invalid MAC address \"%s\". Valid format xx:xx:xx:xx:xx:xx" + END
NO_IMC_OR_CSV = BEG + ": Error: Either an destination analysis CSV (-v) or IMC'19 software"\
                " directory (-s) is needed." + END
INVAL_DST = BEG + ": Error: \"%s\" is not a valid destination type."\
            " Choose from \"fqdn\", \"org\", and \"sld\"." + END
INVAL_PLT = BEG + ": Error: \"%s\" is not a valid plot type. Choose from \"BarHPlot\" and"\
            " \"PiePlot\"." + END
NON_POS = BEG + ": Error: %s must be a positive %s. Received \"%s\"." + END

