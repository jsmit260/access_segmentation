import os
import ipaddress
import optparse
import random
import vagrant
import time

class IPer():
    def __init__(self, ip_range):
        self.ip_range = ipaddress.IPv4Network('192.168.0.0/24')
    
    def get_ips(netrange):
        hosts = list(ipaddress.ip_network(netrange).hosts())
        ten_percent = len(hosts)*.1
        the_choosen = random.choices(hosts,k=int(ten_percent))
        return the_choosen

parser = optparse.OptionParser()
parser.add_option("-r", "--range", dest='range',
        help="enter your network range(s)") 
parser.add_option("-d", "--destroy", dest='destroy_cmd',
        help="enter your network range(s)") 
parser.add_option("-u", "--up", dest='up_cmd',
        help="enter your network range(s)") 
(options,args) = parser.parse_args()

if options.range == None:
    print(parser.usage)
    exit(0)
else:
    the_range = options.range

if options.destroy_cmd == None:
    destroy_cmd = False # defaults to false for future if statement
else:
    destroy_cmd = options.destroy_cmd

if options.up_cmd == None:
    up_cmd = False # defaults to false for future if statement
else:
    up_cmd = options.up_cmd


ipaddresses = IPer.get_ips(the_range)
list_of_ips = []
for ip in ipaddresses:
    list_of_ips.append(str(ip))



operating_systems = ["minimal/trusty64",
                    "minimal/centos7",
                    "minimal/xenial64",
                    "minimal/wheezy64",
                    "stevs986/ubuntu16.04-webserver"]

# Script write and then execute vagrantfile and vagrant command
path ='C:\\Users\\hax0r\\projects\\loop\\'
with open(path+'list_of_ips.txt','w+') as f:
    for ip in list_of_ips:
        f.write(ip+'\n')
with open(path+'VagrantFile_Template') as f:
    data = f.readlines()
    split_data = ' '.join(data)
    host_names = []
    num_ips = len(list_of_ips)
    print(num_ips)
    for i in range(num_ips):
        host_names.append('server{}'.format(i))
    quoted_host_names = []
    for host_name in host_names:
        quoted_host_names.append("'{}'".format(host_name))
    quoted_ip_list = []
    for ip in list_of_ips:
        quoted_ip_list.append("'{}'".format(ip))

    with open(path+'hostnames.txt','w+') as f:
        for hostname in host_names:
            f.write(hostname+'\n')

    new_hostname_data = split_data.replace('HOST_NAMES', ','.join(quoted_host_names) )
    new_ipaddresses_data = new_hostname_data.replace('HOST_BITS',','.join(quoted_ip_list))
    random_os = random.choices(operating_systems,k=num_ips)
    with open(path+"random_operating_systems_selected.txt",'w+') as f:
        for each_os in random_os:
            f.write(each_os+'\n')
    quoted_random_os =[]
    for each_os in random_os:
        quoted_random_os.append("'{}'".format(each_os))
    new_host_operating_systems = new_ipaddresses_data.replace('HOST_OS', ','.join(quoted_random_os))
    new_N_hosts = new_host_operating_systems.replace('number_of_hosts_to_build', str(num_ips))
    ip_net_split = the_range.split('/')
    ip_net_bits = ip_net_split[0]+'_'+ip_net_split[1]
    vag_file_name = "VagrantFile" 
    with open(path+vag_file_name, 'a+') as outfile:
        outfile.write(new_N_hosts)
v = vagrant.Vagrant()
# Build environment
if up_cmd != False:
    os.chdir(path)
    os.system('vagrant up')

