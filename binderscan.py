#!/usr/bin/env python
import time
import datetime 
import ipaddress
import random
import nmap
import os
import pandas as pd
from tabulate import tabulate
from collections import OrderedDict
import sys
import timeit
import optparse

parser = optparse.OptionParser()
parser.add_option("-r", "--range", dest='ip_range',
        help="ENTER NETWORK RANGE") 

parser.add_option("-u", "--no-udp",action='store_true', dest='no_udp_async',
        help="Disables Async UDP Probes") 

parser.add_option("-n", "--no-nmap",action='store_true', dest='no_nmap_tcp',
        help="Disables Nmap TCP Probes") 

parser.add_option("-a", "--no-tcp_async",action='store_true', dest='no_unicorn_tcp',
        help="Disables Async TCP Probes") 

parser.add_option("-p", "--no-ping",action='store_true', dest='no_ping',
        help="Disables ICMP Probes") 

(options,args) = parser.parse_args()

if options.ip_range == None:
    print(parser.usage)
    exit(0)
else:
    the_range = options.ip_range

if options.no_ping == None:
    no_ping = False
else:
    no_ping = options.no_ping

if options.no_unicorn_tcp == None:
    no_unicorn_tcp = False
else:
    no_unicorn_tcp = options.no_unicorn_tcp

if options.no_nmap_tcp == None:
    no_nmap_tcp = False
else:
    no_nmap_tcp = options.no_nmap_tcp

if options.no_udp_async == None:
    no_udp_async = False
else:
    no_udp_async = options.no_udp_async


start = timeit.default_timer()
top_20_ports = ['80','23','443','21','22','25','3389','110','445','139','143','53','135','3306','8080','1723','111','995','993','5900']
top_100_UDP_Ports = ['7','9','17','19','49','53','67','68','69','80','88','111','120','123','135','136','137','138','139','158','161','162','177','427','443','445','497','500','514','515','518','520','593','623','626','631','996','997','998','999','1022','1023','1025','1026','1027','1028','1029','1030','1433','1434','1645','1646','1701','1718','1719','1812','1813','1900','2000','2048','2049','2222','2223','3283','3456','3703','4444','4500','5000','5060','5353','5632','9200','10000','17185','20031','30718','31337','32768','32769','32771','32815','33281','49152','49153','49154','49156','49181','49182','49185','49186','49188','49190','49191','49192','49193','49194','49200','49201','65024']
ranges = [the_range]
tracking = {}
for range in ranges:
    tracking[range]={'net_class':'',
                     'uphost_count':0,
                     'responsive':{} 
                    }

class IPer():
    def __init__(self, ip_range):
        self.ip_range = ipaddress.IPv4Network('192.168.2.0/24')
    
    def get_samples(host_ips,percentage):
        hosts = host_ips
        ten_percent = len(hosts)*percentage
        choosen1 = random.sample(hosts,int(ten_percent))
        after_choosen1 = list(set(hosts)-set(choosen1))
        choosen2 = random.sample(after_choosen1,int(ten_percent))

        after_choosen2 = list(set(after_choosen1)-set(choosen2))
        choosen3 = random.sample(after_choosen2,(int(ten_percent)))
        
        choosen1_strings = []
        for ip in choosen1:
            choosen1_strings.append(str(ip))
        
        choosen2_strings = []
        for ip in choosen2:
            choosen2_strings.append(str(ip))
            
        choosen3_strings = []
        for ip in choosen3:
            choosen3_strings.append(str(ip))
                                
        return choosen1_strings,choosen2_strings,choosen3_strings
    
    def get_my_local_ip():
        os.system("ip -br address | grep eth0  | cut -d 'P' -f 2 | cut -d ' ' -f 14 | cut -d '/' -f 1 > file.txt")
        with open("file.txt",'r') as f:
            ip = f.read()
            ip_strip = ip.strip()
            return ip_strip

    
                
def fping_sweep(the_range,host_ips,the_class):
    print("[*]RUNNING PING SWEEP AGAINST {}[*]".format(the_range))
    if the_class == "C":
        #scan entire range
        cmd='fping -4 --addr -r 1 -a -i 1 -g {} 2>/dev/null >> fping_uphosts.txt'.format(the_range)
        out = os.system(cmd)

        
    elif the_class == "B":
        #take 10% sample and pingsweep it
        sample1,sample2,sample3 = IPer.get_samples(host_ips,.1)
        cmd = 'fping -4 --addr -r 1 -a -i 1 {} 2>/dev/null >> fping_uphosts.txt'.format(' '.join(sample1))
        out = os.system(cmd)
        
    elif the_class == "A":
        sample1,sample2,sample3 = IPer.get_samples(host_ips,.005)
        cmd = 'fping -4 --addr -r 1 -a -i 1 {} 2>/dev/null >> fping_uphosts.txt'.format(' '.join(sample1))
        out = os.system(cmd)

    # Account results in tracking dict    
    with open('fping_uphosts.txt','r') as f:
        ips = f.readlines()
        if len(ips) > 0:
            scanner_ip = IPer.get_my_local_ip()
            for ip in ips:
                if scanner_ip not in ip:
                    if ip not in tracking[the_range]['responsive'].keys():
                        tracking[the_range]['uphost_count'] += 1
                        tracking[the_range]['responsive'][ip.strip()] = ['ICMP']
                else:
                    pass
    os.system('rm fping_uphosts.txt')
    print("[*]PING SWEEP AGAINST {} COMPLETE[*]".format(the_range))
    
    
def unicorn_ports(the_range,top_20_ports,host_ips):
    sample1,sample2,sample3 = IPer.get_samples(host_ips,.1)
    samples = [sample1,sample2,sample3]
    ips = []
    ports = []

    # sudo unicornscan --immediate -mT -R 1 -r100000 -i eth0 192.168.3.0/24 --ports 80,443,22
    if the_class == "A":
        sample1,sample2,sample3 = IPer.get_samples(host_ips,.05)
        cmd='sudo unicornscan -mTS -r200000 -L 2 {} --ports {} >> unicornscan.out'.format(' '.join(sample1),','.join(top_20_ports))
        print('[*]RUNNING UNICORNSCAN -- TOP 20 PORTS on SAMPLE FROM {}[*]'.format(the_range))
        out = os.system(cmd)
        print('[*]UNICORNSCAN on SAMPLE FROM {} COMPLETE[*]'.format(the_range))

    elif the_class == "B":
        sample1,sample2,sample3 = IPer.get_samples(host_ips,.1)
        cmd='sudo unicornscan -mTS -r200000 -L 2 {} --ports {} >> unicornscan.out'.format(' '.join(sample1),','.join(top_20_ports))
        print('[*]RUNNING UNICORNSCAN -- TOP 20 PORTS on SAMPLE FROM {}[*]'.format(the_range))
        out = os.system(cmd)
        print('[*]UNICORNSCAN on SAMPLE FROM {} COMPLETE[*]'.format(the_range))
    else:
        #Class C
        #sample1,sample2,sample3 = IPer.get_samples(host_ips,.3)
        cmd='sudo unicornscan -mTS -r200000 -L 2 {} --ports {} >> unicornscan.out'.format(the_range,','.join(top_20_ports))
        print('[*]RUNNING UNICORNSCAN -- TOP 20 PORTS on {}[*]'.format(the_range))
        out = os.system(cmd)
        print('[*]UNICORNSCAN on SAMPLE FROM {} COMPLETE[*]'.format(the_range))
    
    unicorn_dict = {}    
    with open('unicornscan.out','r') as f:
        data = f.readlines()
        if len(data) > 0:
            for line in data:
                split_line = line.split('from')
                last = split_line[-1]
                split_last = last.split(' ')
                #print("SPLIT_LAST: {}".format(split_last))
                try:
                    final_ip = split_last[1]
                    split_port_step1 = line.split('[')
                    if len(split_port_step1) > 1:
                        split_port_step2 = split_port_step1[1]
                        split_port_step3 = split_port_step2.split(']')
                        port_number=split_port_step3[0].strip()

                        if unicorn_dict.get(final_ip):
                            if port_number not in unicorn_dict[final_ip]:
                                unicorn_dict[final_ip] += [port_number +" (TCP)"]
                        else:
                            unicorn_dict[final_ip] = [port_number+" (TCP)"]
                except:
                    pass

    for ip_,ports_ in unicorn_dict.items():
        if ip_ not in tracking[the_range]['responsive'].keys():
            tracking[the_range]['uphost_count'] += 1
            tracking[the_range]['responsive'][ip_] = ports_
        elif ports_ not in tracking[the_range]['responsive'][ip_]:
            tracking[the_range]['responsive'][ip_] += ports_
    
    os.system('rm unicornscan.out')

def nmap_top_hundred(the_range,host_ips):
    scanner_ip = IPer.get_my_local_ip()
    print("[*]RUNNING NMAP TOP 100 TCP PORTS -- SAMPLE FROM {}[*]".format(the_range))
    nm = nmap.PortScanner()
    if the_class == "C":
        #scan entire range
        scan_data =nm.scan(hosts=the_range, arguments='-Pn --open -T5 -sS -n --exclude {} --top-ports 100'.format(scanner_ip))
        for each_ip in scan_data['scan'].keys():
            if each_ip not in tracking[the_range]['responsive'].keys():          
                tracking[the_range]['uphost_count'] += 1
                port_list = list(scan_data['scan'][each_ip]['tcp'].keys())
                protocol_and_ports = [str(x)+" (TCP)" for x in port_list]
                tracking[the_range]['responsive'][each_ip]= protocol_and_ports
            else:
                tracking[the_range]['responsive'][each_ip] += protocol_and_ports

        
    elif the_class == "B":
        #take 10% sample and pingsweep it
        sample1,sample2,sample3 = IPer.get_samples(host_ips,.1)
        scan_data =nm.scan(hosts=' '.join(sample1), arguments='-Pn --open -sS -T5 -n --exclude {} --top-ports 100'.format(scanner_ip))
        for each_ip in scan_data['scan'].keys():
            if each_ip not in tracking[the_range]['responsive'].keys():          
                tracking[the_range]['uphost_count'] += 1
                port_list = list(scan_data['scan'][each_ip]['tcp'].keys())
                protocol_and_ports = [str(x)+" (TCP)" for x in port_list]
                tracking[the_range]['responsive'][each_ip]= protocol_and_ports
            else:
                tracking[the_range]['responsive'][each_ip] += protocol_and_ports
        
    elif the_class == "A":
        sample1,sample2,sample3 = IPer.get_samples(host_ips,.005)

        scan_data =nm.scan(hosts=' '.join(sample1), arguments='-Pn --open -T5 -sS -n --exclude {} --top-ports 100'.format(scanner_ip))
        for each_ip in scan_data['scan'].keys():
            if each_ip not in tracking[the_range]['responsive'].keys():          
                tracking[the_range]['uphost_count'] += 1
                port_list = list(scan_data['scan'][each_ip]['tcp'].keys())
                protocol_and_ports = [str(x)+" (TCP)" for x in port_list]
                tracking[the_range]['responsive'][each_ip]= protocol_and_ports
            else:
                port_list = list(scan_data['scan'][each_ip]['tcp'].keys())
                protocol_and_ports = [x+" TCP" for x in port_list]
                tracking[the_range]['responsive'][each_ip] += protocol_and_ports
    print("NMAP TOP 100 TCP PORTS COMPLETE")

def unicorn_udp_ports(the_range,top_20_ports,host_ips):
    sample1,sample2,sample3 = IPer.get_samples(host_ips,.1)
    samples = [sample1,sample2,sample3]
    ips = []
    ports = []
    if the_class == "A":
        sample1,sample2,sample3 = IPer.get_samples(host_ips,.05)
        cmd='sudo unicornscan -mU -r200000 {} --ports {} >> unicornscan_udp.out'.format(' '.join(sample1),','.join(top_20_ports))
        print('[*]RUNNING UNICORNSCAN -- TOP 100 UDP PORTS AGAINST SAMPLE FROM {}[*]'.format(the_range))
        out = os.system(cmd)
        print('[*]UNICORNSCAN of TOP 100 UDP PORTS COMPLETE[*]'.format(the_range))

    elif the_class == "B":
        sample1,sample2,sample3 = IPer.get_samples(host_ips,.1)
        cmd='sudo unicornscan -mU -r200000 {} --ports {} >> unicornscan_udp.out'.format(' '.join(sample1),','.join(top_20_ports))
        print('[*]RUNNING UNICORNSCAN -- TOP 100 UDP PORTS AGAINST SAMPLE FROM {}[*]'.format(the_range))
        out = os.system(cmd)
        print('[*]UNICORNSCAN of TOP 100 UDP PORTS COMPLETE[*]'.format(the_range))
    else:
        #Class C
        #sample1,sample2,sample3 = IPer.get_samples(host_ips,.3)
        cmd='sudo unicornscan -mU -r200000 {} --ports {} >> unicornscan_udp.out'.format(the_range,','.join(top_20_ports))
        print('[*]RUNNING UNICORNSCAN -- TOP 100 UDP PORTS AGAINST SAMPLE FROM {}[*]'.format(the_range))
        out = os.system(cmd)
        print('[*]UNICORNSCAN of TOP 100 UDP PORTS COMPLETE[*]'.format(the_range))
    
    unicorn_dict = {}    
    with open('unicornscan_udp.out','r') as f:
        data = f.readlines()
        if len(data) > 0:
            for line in data:
                split_line = line.split('from')
                last = split_line[-1]
                split_last = last.split(' ')
                #print("SPLIT_LAST: {}".format(split_last))
                try:
                    final_ip = split_last[1]
                    split_port_step1 = line.split('[')
                    if len(split_port_step1) > 1:
                        split_port_step2 = split_port_step1[1]
                        split_port_step3 = split_port_step2.split(']')
                        port_number=split_port_step3[0].strip()

                        if unicorn_dict.get(final_ip):
                            if port_number not in unicorn_dict[final_ip]:
                                unicorn_dict[final_ip] += [port_number+" (UDP)"]
                        else:
                            unicorn_dict[final_ip] = [port_number+" (UDP)"]
                except:
                    pass

    for ip_,ports_ in unicorn_dict.items():
        if ip_ not in tracking[the_range]['responsive'].keys():
            tracking[the_range]['uphost_count'] += 1
            tracking[the_range]['responsive'][ip_] = ports_
        elif ports_ not in tracking[the_range]['responsive'][ip_]:
            tracking[the_range]['responsive'][ip_] += ports_
    
    os.system('rm unicornscan_udp.out')


# LOGIC

for range in ranges:
    # First Ping Sweep Entire Ranges if Class C
        
    host_ips = list(ipaddress.ip_network(range).hosts())
    number_of_hosts = len(host_ips)
    if  number_of_hosts <= 32512:
        the_class = "C"
        # Insert Classification of the given range
        tracking[range]['net_class'] = the_class
        if no_ping == False:
            fping_sweep(range,host_ips, the_class)
        else:
            print('[*]SKIPPING PINGSWEEPS[*]')

        
    # If Class B /16 (65,024) then sample 10% with fping
    elif number_of_hosts  >= 65024 and len(list(ipaddress.ip_network(range).hosts())) < 16777214:
        the_class = "B"
        # Insert Classification of the given range
        tracking[range]['net_class'] = the_class

        if no_ping == False:
            fping_sweep(range,host_ips, the_class)
        else:
            print('[*]SKIPPING PINGSWEEPS[*]')        
    # If Class A /8 (16,777,214)then sample half a 2.5% with fping
    elif number_of_hosts >= 16777214:
        the_class = "A"
        # Insert Classification of the given range
        tracking[range]['net_class'] = the_class
        if no_ping == False:
            fping_sweep(range,host_ips, the_class)
        else:
            print('[*]SKIPPING PINGSWEEPS[*]')        
          
    if tracking[range]['uphost_count'] == 0:
        if no_unicorn_tcp == False:
            unicorn_ports(range,top_20_ports,host_ips)
        else:
            print('[*]SKIPPING ASYNCHRONOUS TCP SCANS[*]') 

    if tracking[range]['uphost_count'] == 0:
        if no_nmap_tcp == False:
            nmap_top_hundred(range,host_ips)
        else:
            print('[*]SKIPPING NMAP TCP SCANS[*]') 

    if tracking[range]['uphost_count'] == 0:
        if no_udp_async == False:
            unicorn_udp_ports(range,top_100_UDP_Ports,host_ips)
        else:
            print('[*]SKIPPING ASYNCHRONOUS UDP SCANS[*]') 

    stop = timeit.default_timer()
    total_time = stop - start

    # output running time in a nice format.
    mins, secs = divmod(total_time, 60)
    hours, mins = divmod(mins, 60)

    time_csv = "%d:%d:%d.\n" %(hours, mins, secs)
    dt = datetime.datetime.now().strftime('%Y-%m-%d-%H%M')
    r = ' '.join(ranges)
    time_log = "{},{},{},{}".format(dt,r,tracking[range]['net_class'],time_csv)
    with open("time.logs","a+") as f:
        print("[*]Writing To Time Log[*]")
        f.write(time_log)
        print("[*]Time Log Updated[*]")

df2 = pd.DataFrame.from_dict(tracking,orient='index')
filename = 'logs/discovery-outfile-run-on-%s.csv'%datetime.datetime.now().strftime('%Y-%m-%d-%H%M')
df2.to_csv(filename,index_label='ip range')
