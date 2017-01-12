#!/usr/bin/python

#-----------------------------------------
# Name:        MBSA parser
# Author:      Sumit Shrivastava
# Version:     v1.0.0
#-----------------------------------------


from xml.etree import ElementTree
import optparse
import glob
import string
import random

def parse_file(file):
    tree = ElementTree.parse(file)
    report = {}
    for node in tree.iter('SecScan'):
        report["DisplayName"] = node.attrib.get('DisplayName')
        report["IP"] = node.attrib.get('IP')
        report["ScanDate"] = node.attrib.get('Date')
        report["MissingPatches"] = []
    for node in tree.iter('UpdateData'):
        id = node.attrib.get('ID')
        if id:
            isinstalled = node.attrib.get('IsInstalled')
            if isinstalled == 'false':
                bid = node.attrib.get('BulletinID')
                if bid:
                    bulletinid = bid
                else:
                    bulletinid = "None"
                idd = node.attrib.get('ID')
                #print "Patch id = " +idd
                severity = node.attrib.get('Severity')
                #print "Severity = "+severity
                dtype = node.attrib.get ('Type')
                #print "Patch type:" + dtype
                for p in node.getiterator('Title'):
                    desc = p.text  
                update = (bulletinid, idd, severity, dtype, desc)
                report["MissingPatches"].append(update)
    return report

def generate_file_report(file):
    op_file_split = file.split("\\")
    op_filename = op_file_split[len(op_file_split) - 1].replace(" ", "_")[:-5] + "_" + random_code(8) + ".htm"
    op_file = open(op_filename, "w")
    #code to analyse
    input_file = open(file, "rt")
    report = parse_file(input_file)
    #code to write output to file
    data = "<!DOCTYPE html><html><head><title>MBSA_Report</title><body>"
    data+="<table border=1><tr><th align='left'>IP: </th><td colspan='4'>" + report['IP'] + "</th></tr>"
    data+="<tr><th align='left'>Display Name: </th><td colspan='4'>" + report["DisplayName"] + "</th></tr>"
    data+="<tr><th align='left'>Scan Date: </th><td colspan='4'>" + report["ScanDate"] + "</th></tr>"
    if len(report["MissingPatches"]) > 0:
        data+="<tr><th>Bulletin ID</th><th>Patch ID</th><th>Title</th><th>Type</th><th>Severity</th></tr>"
        for missing_patch in report["MissingPatches"]:
            bid, idd, severity, dtype, desc = missing_patch
            update_type = {"1":"Critical Update", "2":"Security Update", "3":"Defination Update", "4":"Update Rollup", "5":"Service Pack", "6":"Tool", "7":"Feature Pack", "8":"Update"}
            severity_level = {"0":"", "1":"Low", "2":"Moderate", "3":"Important", "4":"Critical"}
            data+="<tr><td>" + bid + "</td><td>" + idd + "</td><td>" + desc + "</td><td>" + update_type[dtype] + "</td><td>" + severity_level[severity] + "</td></tr>"
    else:
        data += "<tr><td colspan=5>No Missing Patches Found!</td></tr>"
    data += "</table></body></html>"
    op_file.write(data)
    op_file.close()
    print "[+] Output for %s written to %s" %(file, op_filename)

def generate_folder_report(folder):
    op_folder_name = folder.split("\\")
    op_filename = op_folder_name[len(op_folder_name) - 1].replace(" ", "_") + "_" + random_code(8) + ".htm"
    op_file = open(op_filename, "w")
    #code to analyse
    data = "<!DOCTYPE html><html><head><title>MBSA_Report</title><body>"
    files = glob.glob(folder + "\*.mbsa")
    
    #code to write output to file
    for file in files:
        input_file = open(file, "rt")
        report = parse_file(input_file)    
        if len(report["MissingPatches"]) > 0:
            data+="<table border=1><tr><th align='left'>IP: </th><td colspan='4'>" + report['IP'] + "</th></tr>"
            data+="<tr><th align='left'>Display Name: </th><td colspan='4'>" + report["DisplayName"] + "</th></tr>"
            data+="<tr><th align='left'>Scan Date: </th><td colspan='4'>" + report["ScanDate"] + "</th></tr>"
            data+="<tr><th>Bulletin ID</th><th>Patch ID</th><th>Title</th><th>Type</th><th>Severity</th></tr>"
            for missing_patch in report["MissingPatches"]:
                bid, idd, severity, dtype, desc = missing_patch
                update_type = {"1":"Critical Update", "2":"Security Update", "3":"Defination Update", "4":"Update Rollup", "5":"Service Pack", "6":"Tool", "7":"Feature Pack", "8":"Update"}
                severity_level = {"0":"", "1":"Low", "2":"Moderate", "3":"Important", "4":"Critical"}
                data+="<tr><td>" + bid + "</td><td>" + idd + "</td><td>" + desc + "</td><td>" + update_type[dtype] + "</td><td>" + severity_level[severity] + "</td></tr>"
            data += "</table><br/>"
            print "[+] Output for %s written to %s" %(file, op_filename)
        else:
            print "[+] %s did not had any missing patches." %(file)
    data+="</body></html>"
    op_file.write(data)
    op_file.close()
    print"[+] Output for files in %s written to %s" %(folder, op_filename)

def random_code(count = 6):
    random_str = ""
    data = string.letters + string.digits
    for i in range(0, count):
        random_str += random.choice(data)
    return random_str

def main():
    optionParser = optparse.OptionParser("%prog [options].\n\rThis program is used to Parse MBSA report for Missing Patches.\n\r"
                                         "Created By: Sumit Shrivastava\n\r")
    optionParser.add_option("-F", "--folder", dest="folder", type="string", help="Folder containing multiple MBSA reports")
    optionParser.add_option("-f", "--file", dest="file", type="string", help="MBSA report file")
    options, args = optionParser.parse_args()

    if not(options.folder) and not(options.file):
        optionParser.print_help()
        exit(1)
    else:
        if options.folder:
            #Call report generation folder
            generate_folder_report(options.folder)
                
        if options.file:
            #Call report generation file
            generate_file_report(options.file)

if __name__ == "__main__":
    main()