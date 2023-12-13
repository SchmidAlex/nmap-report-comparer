# NRC (nmap report comparer)

## Overview
This Python script is designed to compare the results of two Nmap scans and highlight the differences. It is particularly useful for cybersecurity analysts to track changes in the network environment.

## Prerequisites
- Python 3.x
- Nmap XML output files

## Installation
No additional libraries are required for this script. It uses standard Python libraries.

## Usage
The script requires two Nmap XML output files - one representing an older scan and another for a more recent scan. It compares these files and outputs the differences, highlighting new or removed hosts and ports.

To run the script, use the following command:

```bash
python3 nmap_compare.py -o [old_file].xml -n [new_file].xml
```

Where:
- `[old_file].xml` is the file path to the older Nmap scan result.
- `[new_file].xml` is the file path to the newer Nmap scan result.

## Important Note
If you encounter issues running this script on a Linux system, it may be due to file format discrepancies. You might need to modify the file format by opening the script in vi and setting the file format to Unix. To do this, open the file in vi and write:

```vi
:set ff=unix
```

## Functionality
The script performs the following actions:
1. Parses the provided Nmap XML output files.
2. Extracts information about hosts and open ports.
3. Compares the old and new scan results.
4. Outputs the differences to a text file, highlighting new or removed hosts and ports.

## Limitations
- The script currently only supports IPv4 addresses.
- It is designed to work with standard Nmap output in XML format.

## Disclaimer
This tool is intended for legal and ethical use only. Always ensure you have permission to scan and analyze networks.

## Contribution
Feedback and contributions to this script are welcome. Please adhere to standard coding practices when making modifications.
