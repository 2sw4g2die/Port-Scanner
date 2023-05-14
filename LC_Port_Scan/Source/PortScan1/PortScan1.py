"""
Author: Lana
Email: Lana.Cossettini@studytafensw.edu.au
Copyright: Gelos Enterprises
License: Proprietary
Updated: 21 / 11 / 2022
Version 1.0.1
status: Development
Overview: scans ports on network inputted
"""

import socket
import sys
import win32evtlog
import win32evtlogutil
import ipaddress
import datetime


def main():
    try:
        print("PORT SCANNER")
        print("Enter Network address to be scanned!")
        o1 = input("1st Octet: ")
        o2 = input("2nd Octet: ")
        o3 = input("3rd Octet: ")
        o4 = input("4th Octet: ")
        sn = input("subnet: / ")

        if int(o1) >= 0 and int(o1) <= 255 and int(o2) >= 0 \
        and int(o2) <= 255 and int(o3) >= 0 and int(o3) <= 255 \
        and int(o4) >= 0 and int(o4) <= 255 and int(sn) >= 0 \
        and int(sn) <= 32:

            net_add = list(ipaddress.IPv4Network("{}.{}.{}.{}/{}".format(o1,o2,o3,o4,sn)))
            net_list = net_add[11::2]

            port_txt = open("Ports.txt", "r")
            port_num = port_txt.read().split()

            for ports in port_num:
                if int(ports) <= 1 or int(ports) >= 65535:
                    print("Port Number Invalid...")
                    invalid_port("The requested port is invalid,", b"invalid port")
                port_scan(net_list, ports)  # scans ports
        else:
            print("Network Address or Subnet Invalid...")

    except FileNotFoundError:
        print("File Not Found...")

    except OverflowError:
        print("Port Number Invalid...")


def port_scan(network, port):
    try:
        log = []
        log_txt = open("ip_port_log.txt", "a")
        scan_time = datetime.datetime.now()

        log_txt.write("scan date:" + str(scan_time) + "\n")

        for host in network:
            socket_cred = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_cred.settimeout(0.5)
            port_res = socket_cred.connect_ex((str(host), int(port)))
            if port_res == 0:
                result = "Port Number {} is open on {}!".format(port, host)
                print(result)
                log.append(result)
                log_txt.write(result + "\n")

            else:
                result = "Port Number {} is closed on {}!".format(port, host)
                print(result)
                log.append(result)
                log_txt.write(result + "\n")

            socket_cred.close()

    except KeyboardInterrupt:
        print("Program Interrupted...")
        sys.exit()
    event_log(log)


def event_log(log_list):
    EVT_APP_NAME = "Port Scanner"
    EVT_ID = 7040
    EVT_CATEG = 9876
    EVT_STRS = [status for status in log_list]
    EVT_TYPE = win32evtlog.EVENTLOG_WARNING_TYPE
    EVT_DATA = b"Event Data"
    win32evtlogutil.ReportEvent(EVT_APP_NAME, EVT_ID, eventCategory=EVT_CATEG, eventType=EVT_TYPE, strings=EVT_STRS, data=EVT_DATA)


def invalid_port(strings, data):
    EVT_APP_NAME = "Invalid Port"
    EVT_ID = 7041
    EVT_CATEG = 9877
    EVT_STRS = ["Port is not valid. "]
    EVT_TYPE = win32evtlog.EVENTLOG_ERROR_TYPE
    EVT_DATA = b"Invalid Port"
    win32evtlogutil.ReportEvent(EVT_APP_NAME, EVT_ID, eventCategory=EVT_CATEG, eventType=EVT_TYPE, strings=EVT_STRS, data=EVT_DATA)


main()
