#!/usr/bin/env python

import argparse
import io
import subprocess
import sys
import os
import xml.etree.ElementTree as elementTree
from datetime import datetime

def run_command(command):
    print("\nRunning command: "+' '.join(command))
    sp = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ""
    while True:
        try:
            out = sp.stdout.read(1).decode('utf-8')
            if out == '' and sp.poll() != None:
                break
            if out != '':
                output += out
                sys.stdout.write(out)
                sys.stdout.flush()
        except UnicodeDecodeError as e:
            print("UnicodeDecodeError: ", e)
            continue
    return output


def extract_information(newFile) :
    try:
        treeTCP = elementTree.parse(newFile)
    except elementTree.ParseError as e:
        print("Compare elementTree.ParseError: ", e)
        cleanedData = clean_xml_data(newFile)
        treeTCP = elementTree.parse(io.StringIO(cleanedData))
        pass

    overview = {}
    tempHost = None
    rootTCP = treeTCP.getroot()
    for child in rootTCP.findall("host") :
        for host in child.findall("address") :
            if host.attrib['addrtype'] == 'ipv4' :
                tempHost = str(host.attrib['addr'])
                if tempHost not in overview.keys() :
                    overview[tempHost] = {}
        for ports in child.findall('ports') :
            for port in ports.findall('port') :
                if port.find('state').attrib['state'] == 'open' :
                    overview[tempHost][str(port.attrib['portid'])] = {
                        'protocol': str(port.attrib['protocol']),
                        'state': str(port.find('state').attrib['state']) if 'state' in port.find('state').attrib else "no_state",
                        'name': str(port.find('service').attrib['name']) if 'name' in port.find('service').attrib else "no_name",
                        'product': str(port.find('service').attrib['product']) if 'product' in port.find('service').attrib else "no_product",
                        'versionnumber': str(port.find('service').attrib['version']) if 'version' in port.find('service').attrib else "no_version",
                        'conf': str(port.find('service').attrib['conf']) if 'conf' in port.find('service').attrib else "no_conf"
                    }
    
    return overview


######### Compares the old scan and the new one and writes the difference into a txt-file #########
def compare(overview, oldFile, directory):
    cmd = ["touch", directory + "/nmap_result_difference.txt"]
    run_command(cmd)

    oldOverview = {}
    tempHost = None
    if os.path.isfile(oldFile) :
        try:
            oldTreeTCP = elementTree.parse(oldFile)
        except elementTree.ParseError as e:
            print("Compare elementTree.ParseError: ", e)
            cleanedData = clean_xml_data(oldFile)
            oldTreeTCP = elementTree.parse(io.StringIO(cleanedData))
            pass
        oldRootTCP = oldTreeTCP.getroot()
        for child in oldRootTCP.findall("host") :
            for host in child.findall("address") :
                if host.attrib['addrtype'] == 'ipv4' :
                    tempHost = str(host.attrib['addr'])
                    if tempHost not in oldOverview.keys() :
                        oldOverview[tempHost] = {}
            for ports in child.findall('ports') :
                for port in ports.findall('port') :
                    if port.find('state').attrib['state'] == 'open' :
                        oldOverview[tempHost][str(port.attrib['portid'])] = {
                            'protocol': str(port.attrib['protocol']),
                            'state': str(port.find('state').attrib['state']) if 'state' in port.find('state').attrib else "no_state",
                            'name': str(port.find('service').attrib['name']) if 'name' in port.find('service').attrib else "no_name",
                            'product': str(port.find('service').attrib['product']) if 'product' in port.find('service').attrib else "no_product",
                            'versionnumber': str(port.find('service').attrib['version']) if 'version' in port.find('service').attrib else "no_version",
                            'conf': str(port.find('service').attrib['conf']) if 'conf' in port.find('service').attrib else "no_conf"
                        }

    outfile = open(directory + "/nmap_result_difference.txt", "at")
    outfile.write("New detected Hosts and Ports: \n\n")

    for host in overview:
        if host in oldOverview:
            for port in overview[host]:
                if port in oldOverview[host]:
                    if overview[host][port]['protocol'] == oldOverview[host][port]['protocol']:
                        pass
                    else: 
                        outfile.write(host + ":\nport\t\twhats new\t\tname\n" + port + "/" + overview[host][port]['protocol'] + "\t\tprotocol\t\t\t" + overview[host][port]['name'] + "\n\n")
                        print("New Protocol for " + host + " detected: " + port + "/" + overview[host][port]['protocol'] + " name: " + overview[host][port]['name']) 
                else:
                    outfile.write(host + ":\nport\t\twhats new\t\tname\n" + port + "/" + overview[host][port]['protocol'] + "\t\tport\t\t\t" + overview[host][port]['name'] + "\n\n")
                    print("New Port for " + host + " detected: " + port + "/" + overview[host][port]['protocol'] + " name: " + overview[host][port]['name'])
        else:
            outfile.write("new host detected:")
            outfile.write(host + ":\nport\t\tname\n")
            for newPorts in overview[host]:
                outfile.write(newPorts + "/" + overview[host][newPorts]['protocol'] + "\t" + overview[host][newPorts]['name'] + "\n\n")

    outfile.write("\nPorts and hosts which got detected in the last scan, but not in the new one: \n\n")

    for host in oldOverview:
        if host in overview:
            for port in oldOverview[host]:
                if port in overview[host]:
                    if oldOverview[host][port]['protocol'] == overview[host][port]['protocol']:
                        pass
                    else:
                        outfile.write(host + ":\nport\t\twhats missing\t\tname\n" + port + "/" + oldOverview[host][port]['protocol'] + "\t\tprotocol\t\t\t" + oldOverview[host][port]['name'] + "\n")
                        print("Old Protocol for " + host + " not detected: " + port + "/" + oldOverview[host][port]['protocol'] + " name: " + oldOverview[host][port]['name'])
                else:
                    outfile.write(host + ":\nport\t\twhats missing\t\tname\n" + port + "/" + oldOverview[host][port]['protocol'] + "\t\tport\t\t\t" + oldOverview[host][port]['name'] + "\n")
                    print("Old Port for " + host + " not detected: " + port + "/" + oldOverview[host][port]['protocol'] + " name: " + oldOverview[host][port]['name'])
        else:
            outfile.write("old host not detected:\n")
            outfile.write(host + ":\nport\t\tname\n")
            for oldPorts in oldOverview[host]:
                outfile.write(oldPorts + "/" + oldOverview[host][oldPorts]['protocol'] + "\t" + oldOverview[host][oldPorts]['name'] + "\n")
            print("Old Host not detected: " + host + ":" + str(oldOverview[host]))

    outfile.flush()
    outfile.close()


######### Function to clean XML-Data, when there are some binary data in it like "ssl/radan-ht@" (happened once) #########
def clean_xml_data(filePath):
    with open(filePath, 'r') as file:
        data = file.read()
    cleanedData = ''.join(char if 32 <= ord(char) <= 126 else ' ' for char in data)
    return cleanedData

#
#            MAIN
#################################################################################

def main():
    parser = argparse.ArgumentParser(description="Port/Service enumaration tool.")

    parser.add_argument("-o", "--old", dest="old", help="Absolute path to old .xml output file from nmap")
    parser.add_argument("-n", "--new", dest="new", help="Absolute path to new .xml output file from nmap to compare with the old one")

    args = parser.parse_args()

    if not args.old :
        print("Missing parameter -o -> \"Old .xml output file from nmap\"")
        return
    
    if not args.new :
        print("Missing parameter -n -> \"New .xml output file from nmap to compare with the old one\"")
        return

    scriptDir = os.path.dirname(__file__)
    old = args.old
    new = args.new

    overview = extract_information(new)
    compare(overview, old, scriptDir)


if __name__ == '__main__' :
    main()