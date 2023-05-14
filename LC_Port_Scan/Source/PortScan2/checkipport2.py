"""
Author: Lana
Email: Lana.Cossettini@studytafensw.edu.au
Copyright: Gelos Enterprises
License: Proprietary
Updated: 21 / 11 / 2022
Version 1.0.2
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
        net_add = list(ipaddress.IPv4Network("192.168.10.0/28"))
        net_list = net_add[11::2]  # does not scan first 10 addresses or even numbered addresses
        port_txt = open("Ports.txt", "r")
        port_num = port_txt.read().split()

        for ports in port_num:
            if int(ports) <= 1 or int(ports) >= 65535:  # checks validity of ports
                print("Port Number Invalid, Please enter a valid Port Number!")
                invalid_port("The requested port is invalid,", b"invalid port")
            port_scan(net_list, ports)  # scans ports
            print(port_num)

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
            socket_credentials = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_credentials.settimeout(0.5)
            port_res = socket_credentials.connect_ex((str(host), int(port)))
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

            socket_credentials.close()

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
    win32evtlogutil.ReportEvent(EVT_APP_NAME, EVT_ID, eventCategory=EVT_CATEG, eventType=EVT_TYPE, strings=EVT_STRS,
                                data=EVT_DATA)


def invalid_port(strings, data):
    EVT_APP_NAME = "Invalid Port"
    EVT_ID = 7041
    EVT_CATEG = 9877
    EVT_STRS = ["Port is not valid."]
    EVT_TYPE = win32evtlog.EVENTLOG_ERROR_TYPE
    EVT_DATA = b"Invalid Port"
    win32evtlogutil.ReportEvent(EVT_APP_NAME, EVT_ID, eventCategory=EVT_CATEG, eventType=EVT_TYPE, strings=EVT_STRS,
                                data=EVT_DATA)


main()
