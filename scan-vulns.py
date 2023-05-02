import socket
import struct
import netifaces as ni
import subprocess
import time

logo = """
 __      ___         _     _____ _          ___        _      ___      __  __       __   __    _              _    _ _ _ _        
 \ \    / / |_  __ _| |_  |_   _| |_  ___  | __|  _ __| |__  |_ _|___ |  \/  |_  _  \ \ / /  _| |_ _  ___ _ _| |__(_) (_) |_ _  _ 
  \ \/\/ /| ' \/ _` |  _|   | | | ' \/ -_) | _| || / _| / /   | |(_-< | |\/| | || |  \ V / || | | ' \/ -_) '_| '_ \ | | |  _| || |
   \_/\_/ |_||_\__,_|\__|   |_| |_||_\___| |_| \_,_\__|_\_\  |___/__/ |_|  |_|\_, |   \_/ \_,_|_|_||_\___|_| |_.__/_|_|_|\__|\_, |
                                                                              |__/                                           |__/ 
"""
print(logo)

interfaces = ni.interfaces()

active_interface = None
for interface in interfaces:
    try:
        ifaddresses = ni.ifaddresses(interface)
        ip = ifaddresses[ni.AF_INET][0]['addr']
        if ip.startswith("127.") or ip.startswith("169.254."):
            continue
        else:
            active_interface = interface
            break
    except:
        continue


subprocess.run(["ifconfig",active_interface,"down"])
result = subprocess.run(['sudo', 'macchanger', '--random', active_interface], stdout=subprocess.PIPE)
subprocess.run(["ifconfig",active_interface,"up"])

print(result.stdout.decode())

print("Network scanning starts. Please be patient. The scan takes between 5 and 20 minutes. This time varies depending on the number of devices connected to the network.")

counter = 5

while counter > 0:
    print(counter,"starts in seconds...")
    time.sleep(1)
    counter -= 1


def get_gateway_and_ip_range():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip_address = s.getsockname()[0]
    s.close()
    
    ip_address_parts = local_ip_address.split('.')
    subnet_mask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << (32 - 24))))
    subnet_mask_parts = subnet_mask.split('.')
    network_address_parts = [str(int(ip_address_parts[i]) & int(subnet_mask_parts[i])) for i in range(4)]
    network_address = '.'.join(network_address_parts)
    
    gateway_address = socket.gethostbyname(socket.gethostname())
    
    ip_range_start = network_address
    ip_range_end = network_address
    
    return gateway_address, ip_range_start, ip_range_end

gateway_address, ip_range_start, ip_range_end = get_gateway_and_ip_range()
if gateway_address == "":
    exit(0)

print("Gateway IP :", gateway_address)
ip_range = ip_range_start + "-" + str(254)
print("IP Range:", ip_range,"\n")

import nmap

nm = nmap.PortScanner()

target = ip_range

nm.scan(hosts=target, arguments='nmap -sS -Pn -sV -n -p- -r -O --script vuln')

for host in nm.all_hosts():
    print("\n----------------------------------------------------------------------------------")
    print("Host : %s (%s)" % (host, nm[host].hostname()))
    print("State : %s" % nm[host].state())
    for proto in nm[host].all_protocols():
        
        print("Protocol : %s" % proto)
 
        lport = nm[host][proto].keys()
        for port in lport:

            state = nm[host][proto][port]['state']
            name = nm[host][proto][port]['name']
            product = nm[host][proto][port]['product']
            version = nm[host][proto][port]['version']
            extra_info = nm[host][proto][port]['extrainfo']
            if 'script' in nm[host][proto][port]:
                if 'vulners' in nm[host][proto][port]['script']:
                    script_out = nm[host][proto][port]['script']['vulners']
            else:
                script_out = ''
            print(script_out)
            print("Port : %s\tState : %s\tService : %s\tProduct : %s\tVersion : %s\tExtra Info : %s" % (port, state, name, product, version, extra_info))


