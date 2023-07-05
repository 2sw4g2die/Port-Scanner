# Port-Scanner
TAFE Scripts for Networking

Program scans for open ports on user specified networks.

Specifications/functionalities:
1. The user will identify the range of computers to be check by providing a subnet prefix and subnet mask e.g., subnet prefix 192.168.0 with subnet mask of 255.255.255.0. This input will need to be validated to ensure a valid subnet prefix and subnet mask values is used.
2. The ports are defined in a file (ports.txt) which will be imported at the start of the script. You may assume that valid ports have been entered in this file. 
3. The script will generate IP addresses which fall within the user's nominated range and adheres to the following requirements: 
  - The top ten (10) IP addresses will be reserved for printers and servers and can be skipped 
  - The script must skip every IP address that is evenly numbered
4. For each of the IP addresses in the user's nominated range:  
  - Scan all ports  
  - Output the status of each port including "port open" or "port closed" 
  - IP address that are unavailable for port scanning are to be noted as "unavailable" 
5. The script must output the IP address and port status to; Console, Log file (ip_port_log.txt), and Windows event log for later viewing in Windows Event Viewer (IP Addresses Only) 
6. All code is to be developed using Python and run on a current MS Windows OS
